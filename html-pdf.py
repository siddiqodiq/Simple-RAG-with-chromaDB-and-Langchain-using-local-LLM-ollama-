import os
from pyppeteer import launch
import asyncio

# Daftar URL yang akan diubah menjadi PDF
urls = [
    "https://github.com/sqlmapproject/sqlmap",
]

# Membuat direktori ./data jika belum ada
if not os.path.exists('./data'):
    os.makedirs('./data')

async def save_page_as_pdf(url, output_path):
    # Tentukan jalur ke Chromium yang sudah terinstal
    browser = await launch(
        headless=True,
        executablePath='E:/Kuliah/Akademik/TA/RAG/chrome/win64-133.0.6943.126/chrome-win64/chrome.exe'  # Ganti dengan jalur Chromium Anda
    )
    page = await browser.newPage()

    # Mengarahkan ke URL
    await page.goto(url, {'waitUntil': 'networkidle2'})

    # Menyimpan halaman sebagai PDF
    await page.pdf({'path': output_path, 'format': 'A4'})

    # Menutup browser
    await browser.close()

async def main():
    for i, url in enumerate(urls):
        # Menentukan nama file PDF
        output_path = f'./data/page_{i+1}.pdf'
        
        # Mengubah halaman web menjadi PDF
        await save_page_as_pdf(url, output_path)
        print(f'Saved {url} to {output_path}')

# Menjalankan fungsi utama
asyncio.get_event_loop().run_until_complete(main())