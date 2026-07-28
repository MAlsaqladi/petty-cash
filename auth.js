/**
 * طبقة جلسة مشتركة بين الصفحات الثلاث:
 * login.html (بوابة الدخول واختيار النظام)
 * index.html (نظام إدارة العهد النقدية)
 * secondments.html (نظام إدارة الانتدابات وتذاكر السفر)
 *
 * تُستخدم sessionStorage (وليس localStorage) حتى تُمسح الجلسة تلقائيًا
 * عند إغلاق التبويب/المتصفح، وتبقى خاصة بكل تبويب على حدة.
 */
const Auth = (function(){
  const KEY = 'cs_session_v1';

  function saveSession(user){
    try{
      sessionStorage.setItem(KEY, JSON.stringify({ user, ts: Date.now() }));
    }catch(e){ /* تجاهل — بعض المتصفحات في وضع خاص قد تمنع sessionStorage */ }
  }

  function readSession(){
    try{
      const raw = sessionStorage.getItem(KEY);
      if(!raw) return null;
      const parsed = JSON.parse(raw);
      return (parsed && parsed.user) ? parsed.user : null;
    }catch(e){ return null; }
  }

  function clearSession(){
    try{ sessionStorage.removeItem(KEY); }catch(e){}
  }

  function goToLogin(){
    window.location.href = 'login.html';
  }

  return { saveSession, readSession, clearSession, goToLogin, KEY };
})();
