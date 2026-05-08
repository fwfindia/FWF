window.AUTH = {
  async api(url, opts={}){
    // Use relative URLs — Vercel rewrites proxy /api/* to Railway backend
    // Also send Authorization header as fallback (handles cases where Vercel proxy strips Set-Cookie)
    const storedToken = sessionStorage.getItem('admin_token') || sessionStorage.getItem('auth_token');
    const headers = {'Content-Type':'application/json'};
    if(storedToken) headers['Authorization'] = 'Bearer ' + storedToken;
    const res = await fetch(url, {
      method: opts.method||'GET',
      headers,
      body: opts.body?JSON.stringify(opts.body):undefined,
      credentials: 'include'
    });
    if(!res.ok){
      const err = await res.json().catch(()=>({error:'Request failed'}));
      const e = new Error(err.error||'Request failed');
      e.status = res.status;
      throw e;
    }
    return res.json();
  }
};
