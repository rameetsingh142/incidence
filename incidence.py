import requests
from bs4 import BeautifulSoup
from googlesearch import search # Needs: pip install googlesearch-python
import re
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import webbrowser

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
    """Parses HTML and extracts all visible text."""
    if not html_content:
        return ""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Remove script and style elements
    for script_or_style in soup(["script", "style"]):
        script_or_style.decompose()
        
    # Get text
    text = soup.get_text(separator=' ', strip=True)
    # Replace multiple spaces with a single space
    text = re.sub(r'\s+', ' ', text)
    return text.lower() # Convert to lowercase for easier matching

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
            output_widget.insert(tk.END, "No medical condition entered. Exiting.\n", "incidence_highlight")
            return

        output_widget.insert(tk.END, f"Searching for incidence data on '{medical_condition}' in India...\n", "incidence_highlight")
        output_widget.insert(tk.END, "Disclaimer: This tool provides an automated search and extraction.\n"
                                     "Results are based on web scraping and keyword matching, and may NOT be accurate or complete.\n"
                                     "ALWAYS verify information with authoritative sources.\n\n", "prevalence_highlight")
        output_widget.update()

        query1 = f"incidence of {medical_condition} in India"
        query2 = f"{medical_condition} statistics India official data"
        query3 = f"{medical_condition} prevalence India research"
        search_queries = [query1, query2, query3]

        all_urls_found = set()
        for query in search_queries:
            output_widget.insert(tk.END, f"  Executing search query: \"{query}\"\n", "prevalence_highlight")
            output_widget.update()
            try:
                for url in search(query, num_results=NUM_RESULTS_TO_PROCESS, lang="en"):
                    all_urls_found.add(url)
                    if len(all_urls_found) >= NUM_RESULTS_TO_PROCESS * 2:
                        break
                if len(all_urls_found) >= NUM_RESULTS_TO_PROCESS * 2:
                    break
                time.sleep(REQUEST_DELAY_SECONDS)
            except Exception as e:
                output_widget.insert(tk.END, f"    Error during search with query '{query}': {e}\n", "incidence_highlight")
                output_widget.insert(tk.END, "    This might be due to network issues or Google blocking automated requests.\n"
                                             "    Consider trying again later or using a VPN if the issue persists.\n"
                                             "    For more reliable searches, Google Custom Search API is recommended (requires setup and API key).\n", "prevalence_highlight")
                output_widget.update()
                continue

        if not all_urls_found:
            output_widget.insert(tk.END, "No relevant URLs found. Try refining your search term or check your internet connection.\n", "incidence_highlight")
            progress_bar["value"] = 0
            return

        output_widget.insert(tk.END, f"\nFound {len(all_urls_found)} potential URLs. Processing top ones...\n", "prevalence_highlight")
        output_widget.update()

        overall_findings_count = 0
        processed_urls_count = 0
        urls_to_process = list(all_urls_found)[:NUM_RESULTS_TO_PROCESS * 2]
        progress_bar["maximum"] = min(NUM_RESULTS_TO_PROCESS, len(urls_to_process))

        for url in urls_to_process:
            if processed_urls_count >= NUM_RESULTS_TO_PROCESS:
                break

            output_widget.insert(tk.END, "\n  Source: ", "prevalence_highlight")
            insert_clickable_url(output_widget, url)
            processed_urls_count += 1
            progress_bar["value"] = processed_urls_count
            progress_bar.update()
            html_content = fetch_html(url)

            if html_content:
                page_text = parse_and_extract_text(html_content)
                if not page_text.strip():
                    output_widget.insert(tk.END, "    Could not extract meaningful text from this page.\n", "incidence_highlight")
                    output_widget.update()
                    continue

                context_keywords = ["india"]
                findings = find_incidence_info(page_text, medical_condition, context_keywords)

                # Try to find prevalence data if no incidence data found
                if not findings:
                    # Look for prevalence sentences
                    prevalence_sentences = []
                    sentences = re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|\!)\s', page_text)
                    for sentence in sentences:
                        if (medical_condition.lower() in sentence and "india" in sentence and "prevalence" in sentence):
                            prevalence_sentences.append(sentence.strip())
                    if prevalence_sentences:
                        output_widget.insert(tk.END, "    No direct incidence data found. Prevalence data found:\n", "prevalence_highlight")
                        for prev in prevalence_sentences:
                            output_widget.insert(tk.END, f"      - Prevalence data: \"...{prev}...\"\n", "prevalence_highlight")
                        # Try to extract prevalence value and estimate incidence
                        for prev in prevalence_sentences:
                            match = re.search(r'(\d[\d,\.]*)\s*(million|lakh|crore|thousand|%)?', prev)
                            if match:
                                value = match.group(1).replace(',', '')
                                unit = match.group(2) if match.group(2) else ''
                                try:
                                    prevalence_num = float(value)
                                    if unit == 'million':
                                        prevalence_num = prevalence_num * 1_000_000
                                    elif unit == 'lakh':
                                        prevalence_num = prevalence_num * 100_000
                                    elif unit == 'crore':
                                        prevalence_num = prevalence_num * 10_000_000
                                    elif unit == 'thousand':
                                        prevalence_num = prevalence_num * 1_000
                                    if unit == '%':
                                        output_widget.insert(tk.END, f"      - Cannot estimate incidence from percentage prevalence without population data.\n", "incidence_highlight")
                                        continue
                                    avg_duration_years = 10
                                    estimated_incidence = prevalence_num / avg_duration_years
                                    output_widget.insert(
                                        tk.END,
                                        f"      - Estimated annual incidence ≈ "
                                    )
                                    incidence_str = f"{int(estimated_incidence):,} cases/year"
                                    output_widget.insert(tk.END, incidence_str, "incidence_highlight")
                                    output_widget.insert(
                                        tk.END,
                                        f" (calculated as prevalence {int(prevalence_num):,} ÷ average duration {avg_duration_years} years)\n"
                                        f"        [Estimation: Incidence ≈ Prevalence / Duration]\n"
                                    )
                                except Exception:
                                    output_widget.insert(tk.END, "      - Could not estimate incidence from prevalence data.\n", "incidence_highlight")
                    else:
                        output_widget.insert(tk.END, f"    No specific incidence or prevalence data matching keywords found on this page for '{medical_condition}'.\n", "incidence_highlight")
                else:
                    output_widget.insert(tk.END, "    Extracted incidence data:\n", "incidence_highlight")
                    for finding in findings:
                        if finding.startswith("Incidence data:"):
                            match = re.search(r'(\d[\d,\.]*)', finding)
                            if match:
                                before = finding[:match.start(1)]
                                number = match.group(1)
                                after = finding[match.end(1):]
                                output_widget.insert(tk.END, f"      - ")
                                output_widget.insert(tk.END, before, "incidence_highlight")
                                output_widget.insert(tk.END, number, "incidence_highlight_number")
                                output_widget.insert(tk.END, after + "\n")
                            else:
                                output_widget.insert(tk.END, f"      - ", "incidence_highlight")
                                output_widget.insert(tk.END, finding + "\n", "incidence_highlight")
                        else:
                            output_widget.insert(tk.END, f"      - {finding}\n")
                        overall_findings_count += 1
                output_widget.update()
            time.sleep(REQUEST_DELAY_SECONDS)

        if overall_findings_count == 0:
            output_widget.insert(tk.END, "\nNo specific incidence figures were automatically extracted from the top search results.\n"
                                         "This could mean the information is not readily available in plain text on these pages,\n"
                                         "is in PDF documents (which this script doesn't process), requires login, or the \n"
                                         "search terms need to be more specific.\n"
                                         "Manual review of search results is recommended.\n", "incidence_highlight")
        output_widget.insert(tk.END, "\nSearch and extraction process finished.\n", "prevalence_highlight")
        output_widget.update()
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
