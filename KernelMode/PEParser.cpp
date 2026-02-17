/**
 * @file PEParser.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the implementation of the PEParser class.
 *
 * Implements the logic for reading a PE file, validating its signatures
 * (MZ and PE), and printing formatted information about its various
 * headers to the console.
 */

#include "PEParser.h"
#include <iostream>
#include <fstream>
#include <iomanip>

namespace KernelMode {

    PEParser::PEParser(std::wstring filePath)
        : filePath(std::move(filePath)), dosHeader(nullptr), ntHeaders(nullptr) {}

    bool PEParser::Parse() {
        std::ifstream file(this->filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            std::wcerr << L"[-] Failed to open file: " << this->filePath << std::endl;
            return false;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        this->fileBuffer.resize(static_cast<size_t>(size));
        if (!file.read(this->fileBuffer.data(), size)) {
            std::wcerr << L"[-] Failed to read file into buffer." << std::endl;
            return false;
        }

        if (this->fileBuffer.size() < sizeof(IMAGE_DOS_HEADER)) {
            std::wcerr << L"[-] File is too small to be a PE file." << std::endl;
            return false;
        }

        this->dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(this->fileBuffer.data());
        if (this->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::wcerr << L"[-] Invalid DOS signature (MZ)." << std::endl;
            return false;
        }

        // Validate e_lfanew
        if (this->dosHeader->e_lfanew < 0 || 
            (size_t)this->dosHeader->e_lfanew >= this->fileBuffer.size() || 
            (this->dosHeader->e_lfanew & 0x3) != 0) { // Check for alignment (4 bytes)
            std::wcerr << L"[-] Invalid e_lfanew pointer (OOB or misaligned)." << std::endl;
            return false;
        }

        // Check for integer overflow in header location calculation
        if (this->fileBuffer.size() < (size_t)this->dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64)) {
            std::wcerr << L"[-] File is too small to contain NT headers." << std::endl;
            return false;
        }

        this->ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(this->fileBuffer.data() + this->dosHeader->e_lfanew);
        if (this->ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::wcerr << L"[-] Invalid NT signature (PE)." << std::endl;
            return false;
        }

        if (this->ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            std::wcerr << L"[-] Only 64-bit PE files are supported by this parser." << std::endl;
            return false;
        }

        // --- BUG-001/002 FIX: Strict Section Bounds Checking ---
        if (this->ntHeaders->FileHeader.NumberOfSections > 96) { // 96 is reasonable max for Windows PE
            std::wcerr << L"[-] Suspicious number of sections: " << this->ntHeaders->FileHeader.NumberOfSections << std::endl;
            return false;
        }

        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(this->ntHeaders);
        // Verify section headers fit in file
        size_t sectionsEnd = (size_t)((PBYTE)sectionHeader - (PBYTE)this->fileBuffer.data()) + 
                             (this->ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
        
        if (sectionsEnd > this->fileBuffer.size()) {
             std::wcerr << L"[-] Section headers extend beyond file bounds." << std::endl;
             return false;
        }

        // Verify each section's raw data fits in file
        for (WORD i = 0; i < this->ntHeaders->FileHeader.NumberOfSections; ++i) {
            if (sectionHeader[i].PointerToRawData > 0) {
                 // Check for integer overflow (Pointer + Isze)
                 if (sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData < sectionHeader[i].PointerToRawData ||
                     sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData > this->fileBuffer.size()) {
                     std::wcerr << L"[-] Section " << i << L" data is OOB." << std::endl;
                     return false;
                 }
            }
        }
        // --------------------------------------------------------

        return true;
    }

    void PEParser::DisplayHeaders() {
        if (!this->dosHeader || !this->ntHeaders) {
            std::wcerr << L"[-] PE file not parsed. Call Parse() first." << std::endl;
            return;
        }

        auto print_field = [](const std::string& name, auto value) {
            std::cout << "  " << std::left << std::setw(25) << name
                      << ": 0x" << std::hex << value << " (" << std::dec << value << ")" << std::endl;
        };

        std::cout << "\n--- PE Header Information for: ";
        std::wcout << this->filePath << L" ---\n";

        std::cout << "\n[+] DOS Header\n";
        print_field("Magic", this->dosHeader->e_magic);
        print_field("NT Header Offset", this->dosHeader->e_lfanew);

        std::cout << "\n[+] NT Signature\n";
        print_field("Signature", this->ntHeaders->Signature);

        std::cout << "\n[+] File Header\n";
        print_field("Machine", this->ntHeaders->FileHeader.Machine);
        print_field("Number of Sections", this->ntHeaders->FileHeader.NumberOfSections);
        print_field("Time/Date Stamp", this->ntHeaders->FileHeader.TimeDateStamp);
        print_field("Size of Optional Header", this->ntHeaders->FileHeader.SizeOfOptionalHeader);
        print_field("Characteristics", this->ntHeaders->FileHeader.Characteristics);

        std::cout << "\n[+] Optional Header\n";
        print_field("Magic", this->ntHeaders->OptionalHeader.Magic);
        print_field("Address of Entry Point", this->ntHeaders->OptionalHeader.AddressOfEntryPoint);
        print_field("Image Base", this->ntHeaders->OptionalHeader.ImageBase);
        print_field("Section Alignment", this->ntHeaders->OptionalHeader.SectionAlignment);
        print_field("File Alignment", this->ntHeaders->OptionalHeader.FileAlignment);
        print_field("Size of Image", this->ntHeaders->OptionalHeader.SizeOfImage);
        print_field("Size of Headers", this->ntHeaders->OptionalHeader.SizeOfHeaders);
        print_field("Subsystem", this->ntHeaders->OptionalHeader.Subsystem);
        print_field("Number of RVA and Sizes", this->ntHeaders->OptionalHeader.NumberOfRvaAndSizes);

        std::cout << "\n[+] Section Headers\n";
        // --- BUG-C001 FIX: Validate section table bounds before access ---
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(this->ntHeaders);
        BYTE* sectionTableStart = reinterpret_cast<BYTE*>(sectionHeader);
        size_t sectionTableSize = this->ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
        BYTE* sectionTableEnd = sectionTableStart + sectionTableSize;
        BYTE* fileBufferEnd = reinterpret_cast<BYTE*>(this->fileBuffer.data()) + this->fileBuffer.size();
        
        if (sectionTableEnd > fileBufferEnd) {
            std::cerr << "[-] ERROR: Section table extends beyond file buffer (potential overflow)" << std::endl;
            std::cerr << "    Section table end: 0x" << std::hex << (uintptr_t)sectionTableEnd << std::endl;
            std::cerr << "    File buffer end:   0x" << (uintptr_t)fileBufferEnd << std::dec << std::endl;
            return; // Abort to prevent crash
        }
        // -----------------------------------------------------------------
        
        for (WORD i = 0; i < this->ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
            std::cout << "  [" << i << "] " << sectionHeader->Name << "\n";
            print_field("  - Virtual Size", sectionHeader->Misc.VirtualSize);
            print_field("  - Virtual Address", sectionHeader->VirtualAddress);
            print_field("  - Size of Raw Data", sectionHeader->SizeOfRawData);
            print_field("  - Pointer to Raw Data", sectionHeader->PointerToRawData);
            print_field("  - Characteristics", sectionHeader->Characteristics);
        }
        std::cout << "\n--- End of PE Information ---\n";
    }
}