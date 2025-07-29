#!/usr/bin/env python3
"""
Test script for API analysis functionality
"""

import pandas as pd
import sys
import os

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from neusym_vul import SAPipeline

def test_api_analysis():
    """Test the API analysis functionality"""
    
    # Create a sample DataFrame with API information
    sample_apis = pd.DataFrame({
        'package': ['java.io', 'java.net', 'java.util'],
        'clazz': ['File', 'URL', 'HashMap'],
        'func': ['exists', 'openConnection', 'put'],
        'full_signature': ['boolean exists()', 'URLConnection openConnection()', 'V put(K key, V value)']
    })
    
    print("Sample API data:")
    print(sample_apis)
    print("\n" + "="*50 + "\n")
    
    # Create a mock pipeline instance for testing
    # Note: This is a simplified test - in real usage you'd need proper initialization
    try:
        # Create a minimal pipeline instance
        pipeline = SAPipeline(
            project_name="test_project",
            query="022",
            enable_api_analysis=True,
            api_analysis_batch_size=2,
            test_run=True,
            no_logger=True
        )
        
        # Test the analysis function
        print("Testing API analysis...")
        result_df = pipeline.add_api_analysis_with_gpt(sample_apis)
        
        print("\nResult with analysis:")
        print(result_df)
        
        # Check if analysis column was added
        if 'analysis' in result_df.columns:
            print(f"\n✓ Analysis column successfully added!")
            print(f"Analysis values: {list(result_df['analysis'])}")
        else:
            print("\n✗ Analysis column was not added!")
            
    except Exception as e:
        print(f"Error during testing: {e}")
        print("This is expected if the full pipeline environment is not set up")

if __name__ == "__main__":
    test_api_analysis() 