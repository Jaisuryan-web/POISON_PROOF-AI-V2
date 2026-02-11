// Simulated training console animations
(function(){
  function typeLine(el, text, delay=20) {
    return new Promise(resolve => {
      let i = 0;
      function tick(){
        el.textContent += text.charAt(i);
        i++;
        if(i < text.length){
          setTimeout(tick, delay);
        } else {
          el.textContent += "\n";
          resolve();
        }
      }
      tick();
    });
  }

  async function runDemo(id){
    const el = document.getElementById(id);
    if(!el) return;
    el.textContent = '';
    await typeLine(el, '[INFO] Loading cleaned dataset...');
    await typeLine(el, '[INFO] Training DecisionTreeClassifier...');
    await typeLine(el, '[OK] Accuracy: 0.84');
    await typeLine(el, '[SECURE] Model hash: a41e9f0bcd...');
    await typeLine(el, '[DONE] Model training and verification complete ✅');
  }

  window.TrainConsole = { runDemo };
})();