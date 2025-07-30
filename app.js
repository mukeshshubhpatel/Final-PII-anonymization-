async function anonymize() {
  const text = document.getElementById('inputText').value;
  
  const options = {
    name: document.getElementById('checkName').checked,
    date: document.getElementById('checkDate').checked,
    email: document.getElementById('checkEmail').checked,
    phone: document.getElementById('checkPhone').checked,
    id: document.getElementById('checkID').checked,
    address: document.getElementById('checkAddress').checked,
    zip: document.getElementById('checkZIP').checked,
    hipaa_zip: document.getElementById('checkHIPAAZIP').checked
  };

  try {
    const response = await axios.post('/anonymize', {
      raw_data: text,
      options: options  
    });

    document.getElementById('outputText').innerHTML = response.data.anonymized.replace(/\n/g, "<br>");

  } catch (error) {
    document.getElementById('outputText').textContent = 'Error: ' + error.message;
    console.error('Anonymization failed:', error);
  }
}