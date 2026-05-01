import asyncio 
import aiohttp 
async def test(): 
    async with aiohttp.ClientSession() as s: 
        r = await s.get('http://millisec.edu.az', allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10), ssl=False) 
        print('Status:', r.status, 'Location:', r.headers.get('Location')) 
asyncio.run(test()) 
