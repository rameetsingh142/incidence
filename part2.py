import requests
from bs4 import BeautifulSoup
from googlesearch import search # Needs: pip install googlesearch-python
import re
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import webbrowser

# Add trafilatura for better text extraction from web pages
try:
    import trafilatura
except ImportError:
    trafilatura = None

# --- Configuration ---
# Number of search results to process
NUM_RESULTS_TO_PROCESS = 5
# Pause between requests to be polite to servers
REQUEST_DELAY_SECONDS = 2

# --- Helper Functions ---

def fetch_html(url):
    """Fetches HTML content from a URL."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"    Error fetching {url}: {e}")
        return None

def parse_and_extract_text(html_content):
    """Parses HTML and extracts all visible text using trafilatura if available, else fallback to BeautifulSoup."""
    if not html_content:
        return ""
    # Use trafilatura for better main-text extraction if available
    if trafilatura:
        downloaded = trafilatura.extract(html_content, include_comments=False, include_tables=False)
        if downloaded and len(downloaded) > 100:
            return downloaded.lower()
    # Fallback to BeautifulSoup
    soup = BeautifulSoup(html_content, 'html.parser')
    for script_or_style in soup(["script", "style"]):
        script_or_style.decompose()
    text = soup.get_text(separator=' ', strip=True)
    text = re.sub(r'\s+', ' ', text)
    return text.lower()

def find_incidence_info(text_content, medical_condition, keywords):
    """
    Tries to find sentences or snippets related to incidence.
    This is a heuristic approach and may not be perfectly accurate.
    """
    if not text_content:
        return []

    # Split text into sentences or chunks for better context
    # A simple split by period might not be perfect for all web text.
    # Consider using NLP libraries for better sentence tokenization for more advanced versions.
    sentences = re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|\!)\s', text_content)
    
    potential_findings = []
    
    # Keywords to look for related to incidence/prevalence
    incidence_keywords = ['incidence', 'cases', 'prevalence', 'diagnosed', 'reported', 'rate', 'affected', 'new cases']
    # Keywords for numbers/scale
    number_keywords = ['million', 'thousand', 'lakh', 'crore'] # Added Indian number terms
    # Keywords for timeframe
    time_keywords = ['year', 'annually', 'annual', 'per year']

    # Combine all keywords for initial filtering
    search_terms = [medical_condition.lower()] + [kw.lower() for kw in keywords] + incidence_keywords

    for sentence in sentences:
        # Check if the sentence contains the medical condition and "india"
        if medical_condition.lower() in sentence and "india" in sentence:
            # Check if it also contains any incidence-related keyword
            if any(inc_kw in sentence for inc_kw in incidence_keywords):
                # Look for numbers in this sentence
                # This regex finds numbers, possibly with commas or decimals
                numbers_found = re.findall(r'\b\d{1,3}(?:,\d{3})*(?:\.\d+)?\b|\b\d+\b', sentence)
                
                if numbers_found:
                    # Try to format the finding
                    snippet = sentence
                    
                    # Check for scale keywords like "million"
                    is_million = any(num_kw in sentence for num_kw in number_keywords if num_kw == 'million')
                    is_lakh = any(num_kw in sentence for num_kw in number_keywords if num_kw == 'lakh')
                    is_crore = any(num_kw in sentence for num_kw in number_keywords if num_kw == 'crore')

                    # Check for time frame
                    time_frame_hint = ""
                    if any(time_kw in sentence for time_kw in time_keywords):
                        time_frame_hint = " (likely per year/annually based on context)"
                    
                    # Basic formatting attempt
                    # Instead of extracting just numbers, display the full sentence as incidence data
                    potential_findings.append(f"Incidence data: \"...{snippet.strip()}...\"{time_frame_hint}")

    return potential_findings

def launch_gui():
    root = tk.Tk()
    root.title("Medical Condition Incidence Finder (India)")
    root.geometry("1000x750")
    root.minsize(800, 600)
    root.configure(bg="#f0f4fa")

    # --- Styles ---
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TFrame", background="#f0f4fa")
    style.configure("TLabel", background="#f0f4fa", font=("Arial", 11))
    style.configure("Title.TLabel", font=("Arial", 22, "bold"), foreground="#2a4d69", background="#f0f4fa")
    style.configure("Instr.TLabel", font=("Arial", 11), foreground="#4f4f4f", background="#f0f4fa")
    style.configure("TButton", font=("Arial", 11, "bold"), background="#4fc3f7", foreground="#fff")
    style.map("TButton", background=[("active", "#1976d2")])
    style.configure("TEntry", font=("Arial", 12))
    style.configure("TProgressbar", troughcolor="#e3eafc", background="#4fc3f7", thickness=18)

    # --- Title ---
    title_label = ttk.Label(root, text="Medical Condition Incidence Finder (India)", style="Title.TLabel")
    title_label.pack(pady=(18, 6))

    # --- Instructions ---
    instr = ("Enter a medical condition (e.g., Diabetes, Coronary Heart Disease) to search for its incidence/prevalence in India.\n"
             "Results are extracted from top web sources. Click on a URL to open the source in your browser.")
    instr_label = ttk.Label(root, text=instr, style="Instr.TLabel", wraplength=950, justify="left")
    instr_label.pack(pady=(0, 14))

    # --- Input Frame ---
    input_frame = ttk.Frame(root)
    input_frame.pack(fill="x", padx=18, pady=(0, 8))

    entry_label = ttk.Label(input_frame, text="Medical Condition:", font=("Arial", 12, "bold"), foreground="#1976d2")
    entry_label.pack(side="left", padx=(0, 8))
    entry = ttk.Entry(input_frame, width=40)
    entry.pack(side="left", padx=(0, 10), ipady=3)

    search_btn = ttk.Button(input_frame, text="Search")
    search_btn.pack(side="left", padx=(0, 8))

    clear_btn = ttk.Button(input_frame, text="Clear")
    clear_btn.pack(side="left")

    # --- Progress Bar ---
    progress_bar_frame = tk.Frame(root, bg="#f0f4fa")
    progress_bar_frame.pack(pady=(0, 10))
    progress_bar = ttk.Progressbar(progress_bar_frame, orient="horizontal", length=500, mode="determinate", style="TProgressbar")
    progress_bar.pack()

    # --- Output Frame ---
    output_frame = tk.Frame(root, bg="#f0f4fa", bd=2, relief="groove")
    output_frame.pack(fill="both", expand=True, padx=18, pady=(0, 18))

    # --- Output Text Widget with custom colors ---
    output = scrolledtext.ScrolledText(
        output_frame,
        width=120,
        height=32,
        wrap=tk.WORD,
        font=("Consolas", 11),
        bg="#e3eafc",
        fg="#222",
        insertbackground="#1976d2",
        borderwidth=0,
        highlightthickness=0,
        padx=10,
        pady=10
    )
    output.pack(fill="both", expand=True)

    # Tag configs for highlighting
    output.tag_config("incidence_highlight", foreground="#d7263d", font=("Consolas", 11, "bold"))
    output.tag_config("incidence_highlight_number", foreground="#1976d2", font=("Consolas", 11, "bold"))
    output.tag_config("prevalence_highlight", foreground="#ff9800", font=("Consolas", 11, "bold"))
    output.tag_config("source_url", foreground="#388e3c", underline=1, font=("Arial", 10, "bold"))

    # --- Button Hover Effects ---
    def on_enter(e):
        e.widget.config(style="Hover.TButton")
    def on_leave(e):
        e.widget.config(style="TButton")
    style.configure("Hover.TButton", background="#1976d2", foreground="#fff")

    search_btn.bind("<Enter>", on_enter)
    search_btn.bind("<Leave>", on_leave)
    clear_btn.bind("<Enter>", on_enter)
    clear_btn.bind("<Leave>", on_leave)

    # --- Insert clickable URL with color ---
    def insert_clickable_url(text_widget, url, tag_prefix="url"):
        start_index = text_widget.index(tk.INSERT)
        text_widget.insert(tk.END, url, "source_url")
        end_index = text_widget.index(tk.INSERT)
        tag_name = f"{tag_prefix}_{start_index.replace('.', '_')}"
        text_widget.tag_add(tag_name, start_index, end_index)
        text_widget.tag_bind(tag_name, "<Button-1>", lambda e, url=url: webbrowser.open_new(url))
        text_widget.insert(tk.END, "\n")

    # --- Search Logic ---
    def run_search(medical_condition, output_widget, progress_bar):
        output_widget.delete(1.0, tk.END)
        progress_bar["value"] = 0
        progress_bar.update()
        if not medical_condition:
            output_widget.insert(tk.END, "No medical condition entered.\n", "incidence_highlight")
            return

        query1 = f"incidence of {medical_condition} in India"
        query2 = f"{medical_condition} statistics India official data"
        query3 = f"{medical_condition} prevalence India research"
        search_queries = [query1, query2, query3]

        all_urls_found = []
        for query in search_queries:
            try:
                for url in search(query, num_results=NUM_RESULTS_TO_PROCESS, lang="en"):
                    if url not in all_urls_found:
                        all_urls_found.append(url)
                    if len(all_urls_found) >= NUM_RESULTS_TO_PROCESS * 2:
                        break
                if len(all_urls_found) >= NUM_RESULTS_TO_PROCESS * 2:
                    break
                time.sleep(0.5)
            except Exception as e:
                output_widget.insert(tk.END, f"Error during search: {e}\n", "incidence_highlight")
                output_widget.update()
                continue

        if not all_urls_found:
            output_widget.insert(tk.END, "No relevant URLs found.\n", "incidence_highlight")
            progress_bar["value"] = 0
            return

        urls_to_process = all_urls_found[:NUM_RESULTS_TO_PROCESS * 2]
        progress_bar["maximum"] = min(NUM_RESULTS_TO_PROCESS, len(urls_to_process))
        processed_urls_count = 0

        for url in urls_to_process:
            if processed_urls_count >= NUM_RESULTS_TO_PROCESS:
                break

            insert_clickable_url(output_widget, url)
            processed_urls_count += 1
            progress_bar["value"] = processed_urls_count
            progress_bar.update()
            html_content = fetch_html(url)

            if not html_content or not html_content.strip():
                # If cannot access or extract content, just print the URL and a message
                output_widget.insert(tk.END, "  (Cannot access or extract data from this link)\n", "incidence_highlight")
                output_widget.update()
                time.sleep(0.5)
                continue

            page_text = parse_and_extract_text(html_content)
            if not page_text.strip():
                output_widget.insert(tk.END, "  (Cannot access or extract data from this link)\n", "incidence_highlight")
                output_widget.update()
                time.sleep(0.5)
                continue

            # Limit sentences to first 4000 characters for more context
            sentences = re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|\!)\s', page_text[:4000])
            keywords = [
                "incidence", "prevalence", "mortality", "death", "deaths", "fatality",
                "population affected", "per year", "annual", "annually", "cases", "rate",
                "subjects tested", "sample size", "participants", "surveyed", "enrolled", "year",
                "population", "study population", "sample", "n="
            ]
            relevant_sentences = []
            for sentence in sentences:
                s = sentence.strip()
                if (
                    medical_condition.lower() in s and
                    "india" in s and
                    any(kw in s for kw in keywords)
                ):
                    relevant_sentences.append(s)
                elif (
                    "india" in s and
                    (
                        re.search(r'\b\d{2,}[ ,]*\b(population|subjects|cases|patients|participants|sample|n=)', s)
                        or re.search(r'\b\d{2,}[ ,]*\b(per year|annually|annual|each year)', s)
                    )
                ):
                    relevant_sentences.append(s)

            if len(relevant_sentences) < 2:
                paper_patterns = [
                    r'(?:journal|doi|pubmed|abstract|study|research|publication|volume|issue|authors|published)',
                    r'(?:background|methods|results|conclusion|introduction)'
                ]
                for sentence in sentences:
                    s = sentence.strip()
                    if (
                        "india" in s and
                        any(re.search(pat, s) for pat in paper_patterns)
                    ):
                        relevant_sentences.append(s)

            for s in relevant_sentences:
                if "subjects tested" in s or "sample size" in s or "participants" in s or "surveyed" in s or "enrolled" in s or "study population" in s or "sample" in s or "n=" in s:
                    output_widget.insert(tk.END, s + "\n", "incidence_highlight")
                elif "incidence" in s or "cases" in s or "per year" in s or "annual" in s or "annually" in s:
                    output_widget.insert(tk.END, s + "\n", "incidence_highlight")
                elif "prevalence" in s:
                    output_widget.insert(tk.END, s + "\n", "prevalence_highlight")
                elif "mortality" in s or "death" in s or "deaths" in s or "fatality" in s:
                    output_widget.insert(tk.END, s + "\n", "incidence_highlight")
                elif "population affected" in s or "rate" in s or "population" in s:
                    output_widget.insert(tk.END, s + "\n", "incidence_highlight")
                elif any(re.search(pat, s) for pat in paper_patterns):
                    output_widget.insert(tk.END, s + "\n", "prevalence_highlight")
            output_widget.update()
            time.sleep(0.5)

        progress_bar["value"] = 0

    def on_search():
        medical_condition = entry.get().strip()
        if not medical_condition:
            messagebox.showwarning("Input Required", "Please enter a medical condition.")
            return
        run_search(medical_condition, output, progress_bar)

    def on_clear():
        entry.delete(0, tk.END)
        output.delete(1.0, tk.END)
        progress_bar["value"] = 0

    search_btn.config(command=on_search)
    clear_btn.config(command=on_clear)

    root.mainloop()

if __name__ == "__main__":
    launch_gui()
