#!/usr/bin/env python3
"""
Direct chart generator for Lugh proxy benchmarks.
This script uses hardcoded values from your benchmark results.
"""

import os
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

# Ensure benchmark_results directory exists
os.makedirs('benchmark_results', exist_ok=True)

# Hardcoded benchmark results directly from your benchmark_results.txt
# BenchmarkSmallNoWAF-8       5     359217 ns/op
# BenchmarkSmallWithWAF-8     5     556425 ns/op
# BenchmarkMediumNoWAF-8      5     461942 ns/op
# BenchmarkMediumWithWAF-8    5     443967 ns/op
# BenchmarkLargeNoWAF-8       5    1348750 ns/op
# BenchmarkLargeWithWAF-8     5     624442 ns/op

# Create DataFrame with the hardcoded values
data = [
    {'Payload': 'Small', 'WAF': 'NoWAF', 'TimeMS': 359217 / 1000000},
    {'Payload': 'Small', 'WAF': 'WithWAF', 'TimeMS': 556425 / 1000000},
    {'Payload': 'Medium', 'WAF': 'NoWAF', 'TimeMS': 461942 / 1000000},
    {'Payload': 'Medium', 'WAF': 'WithWAF', 'TimeMS': 443967 / 1000000},
    {'Payload': 'Large', 'WAF': 'NoWAF', 'TimeMS': 1348750 / 1000000},
    {'Payload': 'Large', 'WAF': 'WithWAF', 'TimeMS': 624442 / 1000000}
]

df = pd.DataFrame(data)
print("Using hardcoded benchmark data:")
print(df)

def generate_waf_comparison(df, output_dir):
    """Generate chart comparing performance with and without WAF"""
    # Get unique payload types
    payloads = sorted(df['Payload'].unique())

    # Set up the plot
    plt.figure(figsize=(10, 6))
    bar_width = 0.35
    index = np.arange(len(payloads))

    # Get data for NoWAF and WithWAF
    no_waf_data = []
    with_waf_data = []

    for payload in payloads:
        no_waf_row = df[(df['Payload'] == payload) & (df['WAF'] == 'NoWAF')]
        with_waf_row = df[(df['Payload'] == payload) & (df['WAF'] == 'WithWAF')]

        no_waf_data.append(no_waf_row['TimeMS'].values[0] if len(no_waf_row) > 0 else 0)
        with_waf_data.append(with_waf_row['TimeMS'].values[0] if len(with_waf_row) > 0 else 0)

    # Create the bar groups
    plt.bar(index - bar_width/2, no_waf_data, bar_width, label='Without WAF', color='#3498db')
    plt.bar(index + bar_width/2, with_waf_data, bar_width, label='With WAF', color='#e74c3c')

    # Calculate WAF overhead percentage
    overhead = [(with_waf - no_waf) / no_waf * 100 if no_waf > 0 else 0
                for no_waf, with_waf in zip(no_waf_data, with_waf_data)]

    # Add data labels
    for i, (no_waf, with_waf, over) in enumerate(zip(no_waf_data, with_waf_data, overhead)):
        plt.text(i - bar_width/2, no_waf + 0.05, f"{no_waf:.2f}ms", ha='center')
        plt.text(i + bar_width/2, with_waf + 0.05, f"{with_waf:.2f}ms", ha='center')
        if with_waf > no_waf:
            plt.text(i, max(no_waf, with_waf) + 0.1, f"+{over:.1f}%", ha='center', fontweight='bold', color='red')
        else:
            plt.text(i, max(no_waf, with_waf) + 0.1, f"{over:.1f}%", ha='center', fontweight='bold', color='green')

    # Add labels and title
    plt.xlabel('Payload Size')
    plt.ylabel('Response Time (ms)')
    plt.title('Lugh Proxy Performance: Impact of WAF')
    plt.xticks(index, payloads)
    plt.legend()
    plt.grid(True, alpha=0.3)

    # Save the chart
    plt.tight_layout()
    plt.savefig(f'{output_dir}/waf_impact.png', dpi=300)
    plt.close()

    print(f"Generated WAF impact chart: {output_dir}/waf_impact.png")

def generate_payload_impact(df, output_dir):
    """Generate chart showing the impact of payload size on performance"""
    # Filter just NoWAF data to see payload impact clearly
    no_waf_df = df[df['WAF'] == 'NoWAF'].copy()

    # Map payload types to sizes in KB for x-axis
    size_mapping = {
        'Small': 0.1,   # ~100 bytes
        'Medium': 10,   # 10KB
        'Large': 100    # 100KB
    }

    no_waf_df['SizeKB'] = no_waf_df['Payload'].map(size_mapping)
    no_waf_df = no_waf_df.sort_values('SizeKB')

    # Create line chart
    plt.figure(figsize=(10, 6))
    plt.plot(no_waf_df['SizeKB'], no_waf_df['TimeMS'], 'o-', linewidth=2, markersize=10, color='#2ecc71')

    # Add data labels
    for i, row in no_waf_df.iterrows():
        plt.text(row['SizeKB'], row['TimeMS'] + 0.1, f"{row['TimeMS']:.2f}ms", ha='center')

    # Add labels and title
    plt.xlabel('Payload Size (KB)')
    plt.ylabel('Response Time (ms)')
    plt.title('Lugh Proxy Performance: Impact of Payload Size')
    plt.grid(True, alpha=0.3)

    # Use log scale for x-axis if we have a wide range of payload sizes
    plt.xscale('log')
    plt.xlabel('Payload Size (KB) - Log Scale')

    # Save the chart
    plt.tight_layout()
    plt.savefig(f'{output_dir}/payload_impact.png', dpi=300)
    plt.close()

    print(f"Generated payload impact chart: {output_dir}/payload_impact.png")

def generate_waf_overhead(df, output_dir):
    """Generate chart showing the WAF overhead for different payload sizes"""
    payloads = sorted(df['Payload'].unique())

    # Calculate overhead for each payload size
    overhead_data = []
    for payload in payloads:
        no_waf_row = df[(df['Payload'] == payload) & (df['WAF'] == 'NoWAF')]
        with_waf_row = df[(df['Payload'] == payload) & (df['WAF'] == 'WithWAF')]

        if len(no_waf_row) > 0 and len(with_waf_row) > 0:
            no_waf_time = no_waf_row['TimeMS'].values[0]
            with_waf_time = with_waf_row['TimeMS'].values[0]
            overhead_pct = (with_waf_time - no_waf_time) / no_waf_time * 100

            overhead_data.append({
                'Payload': payload,
                'Overhead': overhead_pct
            })

    overhead_df = pd.DataFrame(overhead_data)

    # Create bar chart
    plt.figure(figsize=(10, 6))
    bars = plt.bar(overhead_df['Payload'], overhead_df['Overhead'], color='#9b59b6')

    # Add data labels
    for bar in bars:
        height = bar.get_height()
        color = 'red' if height > 0 else 'green'
        plt.text(bar.get_x() + bar.get_width()/2., height + 1 if height > 0 else height - 5,
                f'{height:.1f}%', ha='center', fontweight='bold', color=color)

    # Add labels and title
    plt.xlabel('Payload Size')
    plt.ylabel('WAF Overhead (%)')
    plt.title('Lugh Proxy Performance: WAF Overhead Percentage')
    plt.grid(True, alpha=0.3, axis='y')

    # Save the chart
    plt.tight_layout()
    plt.savefig(f'{output_dir}/waf_overhead_pct.png', dpi=300)
    plt.close()

    print(f"Generated WAF overhead chart: {output_dir}/waf_overhead_pct.png")

def generate_summary_table(df, output_dir):
    """Generate a summary table of benchmark results"""
    # Create a pivot table
    pivot_df = df.pivot(index='Payload', columns='WAF', values='TimeMS')

    # Add overhead column
    pivot_df['Overhead (%)'] = (pivot_df['WithWAF'] - pivot_df['NoWAF']) / pivot_df['NoWAF'] * 100

    # Rename columns for clarity
    pivot_df = pivot_df.rename(columns={
        'NoWAF': 'Without WAF (ms)',
        'WithWAF': 'With WAF (ms)'
    })

    # Save as CSV
    pivot_df.to_csv(f'{output_dir}/summary_table.csv')

    # Create HTML table
    html = """
    <html>
    <head>
        <style>
            table { border-collapse: collapse; width: 100%; font-family: Arial, sans-serif; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: right; }
            th { background-color: #f2f2f2; text-align: center; }
            tr:nth-child(even) { background-color: #f9f9f9; }
            th:first-child, td:first-child { text-align: left; }
        </style>
    </head>
    <body>
        <h2>Lugh Proxy Performance Summary</h2>
        <table>
            <tr>
                <th>Payload Size</th>
                <th>Without WAF (ms)</th>
                <th>With WAF (ms)</th>
                <th>Overhead (%)</th>
            </tr>
    """

    for idx, row in pivot_df.iterrows():
        html += f"""
            <tr>
                <td>{idx}</td>
                <td>{row['Without WAF (ms)']:.2f}</td>
                <td>{row['With WAF (ms)']:.2f}</td>
                <td>{row['Overhead (%)']:.1f}%</td>
            </tr>
        """

    html += """
        </table>
    </body>
    </html>
    """

    with open(f'{output_dir}/summary_table.html', 'w') as f:
        f.write(html)

    print(f"Generated summary table: {output_dir}/summary_table.html")

# Generate all charts
generate_waf_comparison(df, 'benchmark_results')
generate_payload_impact(df, 'benchmark_results')
generate_waf_overhead(df, 'benchmark_results')
generate_summary_table(df, 'benchmark_results')

print("\nAll charts generated successfully in the 'benchmark_results' directory.")