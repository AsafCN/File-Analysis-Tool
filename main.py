import requests
import hashlib
import os
import re
import customtkinter as ctk
import sys
import subprocess
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename='app.log', filemode='a', format='%(asctime)s - %(message)s', level=logging.INFO)

API_KEY = 'your-api-key-here'  # Replace with your actual VirusTotal API key
API_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_file_virustotal(file_path):
    if not os.path.isfile(file_path):
        return "File not found."

    file_hash = calculate_sha256(file_path)
    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(API_URL, params=params)

    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 0:
            return "File not found in VirusTotal database."
        elif result['response_code'] == 1:
            positives = result['positives']
            total = result['total']
            scan_date = result['scan_date']
            return f"Scan Results:\nPositive Detections: {positives}/{total}\nScan Date: {scan_date}"
    else:
        return f"Error: {response.status_code} - {response.text}"

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(f"File Analysis Tool - Running on v{sys.version.split()[0]}")
        self.iconbitmap("icon.ico")
        self.geometry("800x600")
        self.resizable(True, True)
        ctk.set_appearance_mode("dark")

        self.font = "Arial"

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.button_frame = ctk.CTkFrame(self)
        self.button_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        self.button_frame.grid_columnconfigure((0, 1), weight=1)

        self.icon = ctk.CTkButton(self.button_frame, width=250, text="Select File", fg_color="#5d11c3", hover_color="#5057eb",
                                  font=ctk.CTkFont(size=20, family=self.font), command=self.get_file)
        self.icon.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.extract_button = ctk.CTkButton(self.button_frame, width=250, text="Analyze File", fg_color="#11c37a", hover_color="#0beb50",
                                            font=ctk.CTkFont(size=20, family=self.font), command=self.analyze_file)
        self.extract_button.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        self.result_text = ctk.CTkTextbox(self, font=ctk.CTkFont(size=14, family=self.font))
        self.result_text.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")

        self.file_path = None

    def get_file(self):
        self.file_path = ctk.filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        
        if self.file_path:
            self.result_text.delete("1.0", ctk.END)
            self.result_text.insert(ctk.END, f"Selected file: {self.file_path}\n")
            logging.info(f"Selected file: {self.file_path}")
            self.extract_button.configure(state="normal")

    def analyze_file(self):
        if self.file_path:
            self.result_text.delete("1.0", ctk.END)
            self.result_text.insert(ctk.END, "Analyzing file... Please wait.\n")
            self.update_idletasks()
            
            vt_result = check_file_virustotal(self.file_path)
            extracted_strings, lang_info = self.extract_strings(self.file_path)
            
            self.display_results(vt_result, lang_info, extracted_strings)

    def extract_strings(self, file_path):
        try:
            try:
                result = subprocess.run(["strings", file_path], capture_output=True, text=True, check=True).stdout
                result = result.replace("""Strings v2.54 - Search for ANSI and Unicode strings in binary images.
Copyright (C) 1999-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

!This program cannot be run in DOS mode.""", "")
                extracted_strings = result.splitlines()
                with open("extracted_strings.txt", 'w') as f:
                    f.write(result)
                logging.info(f"Successfully used 'strings' command.")
            except FileNotFoundError:
                logging.warning("'strings' command not found, using fallback method.")
                with open(file_path, 'rb') as file:
                    data = file.read()
                pattern = re.compile(rb'[\x20-\x7E]{4,}')
                extracted_strings = [s.decode('ascii', errors='ignore') for s in pattern.findall(data)]

            lang_info = self.detect_language(extracted_strings)
            logging.info(f"Language/Framework detection: {lang_info}")

            extracted_strings = extracted_strings

            return extracted_strings, lang_info

        except Exception as e:
            logging.error(f"Error during extraction: {e}")
            return [], f"Error in string extraction: {e}"

    def detect_language(self, strings):
        indicators = {
            "C++": ["std::", "cout", "cin", "vector", "iostream", "nullptr", "class ", "new ", "delete ", "template<"],
            ".NET": ["System.", "Microsoft.", "using System", "public class", "private void", "namespace ", "Assembly"],
            "Go": ["package main", "import (", "func main(", "go routine", "chan ", "defer ", "interface{"],
            "Python": ["import ", "def ", "class ", "if __name__ == \"__main__\":", "print(", "self.", "try:", "except:"],
            "Rust": ["fn main", "let mut", "impl ", "trait ", "pub struct", "use std", "match ", "enum "],
            "Java": ["public class", "public static void main", "System.out.println", "import java.", "extends ", "implements "],
            "JavaScript": ["function ", "const ", "let ", "var ", "document.", "window.", "addEventListener(", "console.log("],
            "PHP": ["<?php", "function ", "echo ", "$_GET", "$_POST", "public function", "namespace "],
            "Ruby": ["def ", "class ", "require '", "attr_accessor", "module ", "puts ", "yield "],
            "Swift": ["import Foundation", "class ", "struct ", "enum ", "var ", "func ", "guard let"],
            "Kotlin": ["fun main(", "val ", "var ", "class ", "object ", "suspend fun", "companion object"],
            "TypeScript": ["interface ", "type ", "export class", "implements ", "extends ", "private ", "public "],
            "Assembly": [".text", ".data", "mov ", "push ", "pop ", "call ", "ret ", "jmp "],
            "Objective-C": ["@interface", "@implementation", "@property", "NSString", "UIViewController", "[self ", "alloc] init]"],
            "Compiled Executable": [".exe", ".dll", ".so", ".dylib", "UPX", "PECompact", "ASPack", "kernel32.dll", "user32.dll", "ADVAPI32.dll"]
        }

        detected = {}
        total_strings = len(strings)

        for lang, patterns in indicators.items():
            count = sum(1 for s in strings for p in patterns if p.lower() in s.lower())
            if count > 0:
                detected[lang] = (count / total_strings) * 100

        if detected:
            sorted_detected = sorted(detected.items(), key=lambda x: x[1], reverse=True)
            return ", ".join([f"{lang} ({score:.2f}%)" for lang, score in sorted_detected if score > 0.1])
        else:
            return "No specific language detected"

    def analyze_file_type(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
            if header.startswith(b'MZ'):
                return "Windows Executable (EXE or DLL)"
            elif header.startswith(b'\x7FELF'):
                return "Linux/Unix Executable (ELF)"
            elif header.startswith(b'\xCA\xFE\xBA\xBE') or header.startswith(b'\xFE\xED\xFA\xCE'):
                return "Mac OS X Executable (Mach-O)"
            else:
                return "Unknown binary format"
        except Exception as e:
            return f"Error analyzing file type: {str(e)}"

    def display_results(self, vt_result, lang_info, extracted_strings):
        self.result_text.delete("1.0", ctk.END)
        
        current_date = datetime.now()
        self.result_text.insert(ctk.END, f"File: {self.file_path}\n")
        self.result_text.insert(ctk.END, f"Analysis Date: {current_date.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        self.result_text.insert(ctk.END, "VirusTotal Results:\n")
        self.result_text.insert(ctk.END, f"{vt_result}\n\n")
        
        self.result_text.insert(ctk.END, "File Type Analysis:\n")
        file_type = self.analyze_file_type(self.file_path)
        self.result_text.insert(ctk.END, f"{file_type}\n\n")
        
        self.result_text.insert(ctk.END, "Language Detection:\n")
        if lang_info == "No specific language detected" or lang_info == "":
            self.result_text.insert(ctk.END, "No specific programming language detected. ")
            self.result_text.insert(ctk.END, "This is common for compiled executables or obfuscated files.\n")
            self.result_text.insert(ctk.END, "The file may be a binary executable, packed, or encrypted.\n\n")
        else:
            self.result_text.insert(ctk.END, f"{lang_info}\n\n")
        
        self.result_text.insert(ctk.END, f"Extracted Strings (showing first {min(1000, len(extracted_strings))}):\n")
        for string in extracted_strings[:1000]:
            self.result_text.insert(ctk.END, f"{string}\n")
        
        if len(extracted_strings) > 1000:
            self.result_text.insert(ctk.END, "\n(Showing first 1000 strings out of {len(extracted_strings)} total)\n")
        elif len(extracted_strings) == 0:
            self.result_text.insert(ctk.END, "No strings were extracted from the file.\n")
        
        self.result_text.see(ctk.END)
        logging.info("Analysis results displayed in GUI")

    def analyze_file(self):
        if self.file_path:
            self.result_text.delete("1.0", ctk.END)
            self.result_text.insert(ctk.END, "Analyzing file... Please wait.\n")
            self.update_idletasks()
            
            vt_result = check_file_virustotal(self.file_path)
            extracted_strings, lang_info = self.extract_strings(self.file_path)
            
            self.display_results(vt_result, lang_info, extracted_strings)

if __name__ == "__main__":
    app = App()
    app.mainloop()
