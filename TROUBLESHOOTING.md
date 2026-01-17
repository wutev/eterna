# Troubleshooting Vault Creation

## Issue: "Nothing happens when I try to create a vault"

This guide will help you diagnose and fix the problem.

---

## Step 1: Open Developer Tools

When the app is running:
1. Press **Ctrl+Shift+I** or **F12** to open DevTools
2. Click the **Console** tab

---

## Step 2: Check for Errors

Look for red error messages in the console. Common errors:

### Error: "window.vault is not defined"
**Problem:** Preload script not loading properly

**Fix:**
```bash
# Restart the app
npm start
```

### Error: "Cannot read properties of undefined"
**Problem:** IPC handlers not registered

**Fix:** Check that main.js has all the vault handlers

---

## Step 3: Test Vault APIs Manually

In the DevTools console, paste this:

```javascript
// Test if vault API is available
console.log('Vault API:', window.vault);

// Test initialization check
window.vault.isInitialized().then(r => console.log('Is initialized:', r));

// Test password validation
window.vault.validatePassword('Test123!').then(r => console.log('Validation:', r));
```

**Expected output:**
```
Vault API: {isInitialized: ƒ, initialize: ƒ, unlock: ƒ, ...}
Is initialized: {initialized: false}
Validation: {valid: true, strength: "medium", ...}
```

---

## Step 4: Try Creating Vault Manually

In the console:

```javascript
// Create vault with test password
await window.vault.initialize('TestPassword123!');
```

**Expected output:**
```
{success: true, strength: "strong"}
```

**If you see an error,** copy the error message.

---

## Step 5: Check App Data Directory

The vault files should be created here:

```
%APPDATA%\eternavault\
```

**On Windows:** Press Win+R, type `%APPDATA%\eternavault`, press Enter

**You should see:**
- `vault-config.json` (after vault creation)
- `vault-data.json` (after vault creation)

**If folder doesn't exist:** App may not have write permissions

---

## Step 6: Common Issues & Fixes

### Issue: "Failed to create vault" notification

**Possible causes:**
1. Password too weak (min 8 characters)
2. Disk full or write permissions issue
3. Backend vault handlers not loaded

**Debug in console:**
```javascript
// Check what's failing
window.vault.initialize('YourPassword123!')
  .then(r => console.log('Success:', r))
  .catch(e => console.error('Error:', e));
```

### Issue: Password strength validation not working

**Try:**
```javascript
// Test validation
await window.vault.validatePassword('weak');
// Should return: {valid: false, ...}

await window.vault.validatePassword('StrongPass123!');
// Should return: {valid: true, strength: "strong", ...}
```

### Issue: Setup button does nothing

**Check console for:**
- "Setting up vault..." (should appear when clicked)
- "Initialize result: ..." (should show result)
- Any error messages

**If no messages appear:**
The click handler might not be attached. Try:
```javascript
// Manually trigger setup
await setup('TestPassword123!');
```

---

## Step 7: Full Diagnostic Test

Copy and run the full test script in console:

```javascript
// Test all vault APIs
async function fullTest() {
  console.log('=== VAULT DIAGNOSTIC TEST ===\n');

  // 1. Check APIs
  console.log('1. Vault API exists:', typeof window.vault !== 'undefined');
  console.log('   Storage API exists:', typeof window.storage !== 'undefined');

  // 2. Test isInitialized
  try {
    const init = await window.vault.isInitialized();
    console.log('2. isInitialized():', init);
  } catch (e) {
    console.error('2. isInitialized() FAILED:', e);
  }

  // 3. Test password validation
  try {
    const valid = await window.vault.validatePassword('Test123!');
    console.log('3. validatePassword():', valid);
  } catch (e) {
    console.error('3. validatePassword() FAILED:', e);
  }

  // 4. Test vault creation
  try {
    console.log('4. Creating test vault...');
    const result = await window.vault.initialize('TestDiagnostic123!');
    console.log('   Result:', result);

    if (result.success) {
      console.log('✅ VAULT CREATED SUCCESSFULLY!');

      // Clean up - delete test vault
      console.log('5. Cleaning up test vault...');
      // Note: You may need to manually delete the files
      console.log('   Delete these files to reset:');
      console.log('   %APPDATA%\\eternavault\\vault-config.json');
      console.log('   %APPDATA%\\eternavault\\vault-data.json');
    } else {
      console.error('❌ VAULT CREATION FAILED:', result.error);
    }
  } catch (e) {
    console.error('4. initialize() FAILED:', e);
  }

  console.log('\n=== TEST COMPLETE ===');
}

fullTest();
```

---

## Step 8: Check Backend Logs

Look at the terminal where you ran `npm start`. Check for:

```
Error: EACCES: permission denied
Error: ENOENT: no such file or directory
```

**If you see these:** App doesn't have write permissions

**Fix:** Run as administrator or check antivirus

---

## Step 9: Verify File Structure

Make sure these files exist:

```
eternavault/
├── main.js           ← Has vault IPC handlers
├── preload.js        ← Exposes window.vault
├── encryption.js     ← Encryption module
├── index.html        ← Frontend
└── package.json
```

**Check encryption.js exists:**
```bash
ls encryption.js
```

**If missing:** Re-download or copy from the implementation files

---

## Step 10: Nuclear Option - Fresh Start

If nothing works:

1. **Delete app data:**
   ```
   %APPDATA%\eternavault\
   ```
   Delete entire folder

2. **Clear Electron cache:**
   ```
   %APPDATA%\eternavault
   ```

3. **Reinstall dependencies:**
   ```bash
   cd eternavault
   rm -rf node_modules
   npm install
   ```

4. **Start fresh:**
   ```bash
   npm start
   ```

---

## Getting Help

If you're still stuck, provide:

1. **Error messages** from console (Ctrl+Shift+I)
2. **Terminal output** from where you ran `npm start`
3. **Test results** from Step 7
4. **OS and Node version:**
   ```bash
   node --version
   npm --version
   ```

---

## Quick Test Checklist

- [ ] DevTools console shows no errors
- [ ] `window.vault` is defined
- [ ] `window.vault.isInitialized()` works
- [ ] Can validate password manually
- [ ] Can create vault manually in console
- [ ] Files appear in %APPDATA%\eternavault
- [ ] "Setting up vault..." appears in console when clicking button
- [ ] No permission errors in terminal

---

**Most common fix:** Just restart the app with `npm start` 🔄
