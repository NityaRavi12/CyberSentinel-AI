#!/usr/bin/env python3
"""
Simple test script for CyberSentinel AI API
"""

import asyncio
import aiohttp
import json

async def test_api():
    """Test the API endpoints"""
    async with aiohttp.ClientSession() as session:
        # Test health endpoint
        async with session.get('http://localhost:8000/health') as response:
            print(f"Health check: {response.status}")
            data = await response.json()
            print(f"Response: {data}")
        
        # Test threat submission
        threat_data = {
            "title": "Suspicious Email Detected",
            "description": "Phishing email attempting to steal credentials",
            "source": "email",
            "source_details": {
                "sender": "suspicious@example.com"
            }
        }
        
        async with session.post(
            'http://localhost:8000/api/v1/threats',
            json=threat_data
        ) as response:
            print(f"\nThreat submission: {response.status}")
            data = await response.json()
            print(f"Response: {json.dumps(data, indent=2)}")
            
            if response.status == 200:
                threat_id = data.get('threat_id')
                if threat_id:
                    # Test getting the threat
                    async with session.get(f'http://localhost:8000/api/v1/threats/{threat_id}') as get_response:
                        print(f"\nGet threat: {get_response.status}")
                        threat_data = await get_response.json()
                        print(f"Threat data: {json.dumps(threat_data, indent=2)}")

if __name__ == "__main__":
    asyncio.run(test_api()) 