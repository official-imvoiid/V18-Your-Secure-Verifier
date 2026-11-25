//! V18 for Windows: device keys in Windows Hello.
//!
//! This addon wraps the Windows `KeyCredentialManager` API (Windows Hello / "Microsoft Passport").
//! - Keys are RSA-2048, made and kept by Windows Hello. On PCs with a TPM, Windows keeps them in
//!   the TPM. The private key never leaves Windows; this code never sees it.
//! - Every signature makes Windows show its own Hello prompt (face, fingerprint or PIN).
//! - Signatures are RSASSA-PKCS1-v1_5 with SHA-256 (the `RS256` row of PROTOCOL.md 3.4).
//!
//! There is no software fallback in this file. If Hello is not set up, calls fail with a
//! `V18HELLO:<Code>` error and the app shows its "PC security check" error screen.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use windows::core::HSTRING;
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialAttestationStatus, KeyCredentialCreationOption, KeyCredentialManager,
    KeyCredentialStatus,
};
use windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType;
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;

/// Every error from this addon starts with this prefix, then a short code, so the TypeScript side
/// can map it to the right screen.
fn hello_err(code: &str, detail: impl std::fmt::Display) -> Error {
    Error::from_reason(format!("V18HELLO:{code}: {detail}"))
}

fn win_err(context: &str, e: windows::core::Error) -> Error {
    hello_err("WinError", format!("{context}: {} (0x{:08X})", e.message(), e.code().0 as u32))
}

fn status_code(s: KeyCredentialStatus) -> &'static str {
    match s {
        KeyCredentialStatus::Success => "Success",
        KeyCredentialStatus::NotFound => "NotFound",
        KeyCredentialStatus::UserCanceled => "UserCanceled",
        KeyCredentialStatus::UserPrefersPassword => "UserPrefersPassword",
        KeyCredentialStatus::CredentialAlreadyExists => "CredentialAlreadyExists",
        KeyCredentialStatus::SecurityDeviceLocked => "SecurityDeviceLocked",
        _ => "UnknownError",
    }
}

/// libuv worker threads have no COM apartment. WinRT needs one, so join the multi-threaded one.
/// A failure here (for example "already initialised") is harmless and ignored.
fn ensure_apartment() {
    unsafe {
        let _ = windows::Win32::System::WinRT::RoInitialize(windows::Win32::System::WinRT::RO_INIT_MULTITHREADED);
    }
}

fn buffer_to_vec(buf: &IBuffer) -> Result<Vec<u8>> {
    let mut arr = windows::core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(buf, &mut arr).map_err(|e| win_err("CopyToByteArray", e))?;
    Ok(arr.to_vec())
}

/// Unpackaged desktop apps cannot pass their window to KeyCredentialManager, so Windows may open
/// the Hello prompt behind our window. We let other processes take the foreground, then look for
/// the Hello prompt window for a few seconds and bring it to the front. This only moves a window;
/// it never touches the prompt's contents.
fn help_prompt_to_front() {
    use windows::Win32::UI::WindowsAndMessaging::{AllowSetForegroundWindow, FindWindowW, SetForegroundWindow, ASFW_ANY};
    unsafe {
        let _ = AllowSetForegroundWindow(ASFW_ANY);
    }
    std::thread::spawn(|| {
        let class = HSTRING::from("Credential Dialog Xaml Host");
        for _ in 0..60 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            unsafe {
                if let Ok(hwnd) = FindWindowW(&class, None) {
                    if !hwnd.is_invalid() {
                        let _ = SetForegroundWindow(hwnd);
                        return;
                    }
                }
            }
        }
    });
}

fn open_credential(name: &str) -> Result<KeyCredential> {
    let op = KeyCredentialManager::OpenAsync(&HSTRING::from(name)).map_err(|e| win_err("OpenAsync", e))?;
    let res = op.join().map_err(|e| win_err("OpenAsync", e))?;
    let status = res.Status().map_err(|e| win_err("Status", e))?;
    if status != KeyCredentialStatus::Success {
        return Err(hello_err(status_code(status), "could not open the Windows Hello key"));
    }
    res.Credential().map_err(|e| win_err("Credential", e))
}

fn public_key_spki(cred: &KeyCredential) -> Result<Vec<u8>> {
    let buf = cred
        .RetrievePublicKeyWithBlobType(CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo)
        .map_err(|e| win_err("RetrievePublicKey", e))?;
    buffer_to_vec(&buf)
}

// ---------------------------------------------------------------------------------------------
// isSupported(): is Windows Hello set up for this Windows account? Never shows a prompt.

pub struct IsSupportedTask;
impl Task for IsSupportedTask {
    type Output = bool;
    type JsValue = bool;
    fn compute(&mut self) -> Result<bool> {
        ensure_apartment();
        let op = KeyCredentialManager::IsSupportedAsync().map_err(|e| win_err("IsSupportedAsync", e))?;
        op.join().map_err(|e| win_err("IsSupportedAsync", e))
    }
    fn resolve(&mut self, _env: Env, out: bool) -> Result<bool> {
        Ok(out)
    }
}

#[napi]
pub fn is_supported() -> AsyncTask<IsSupportedTask> {
    AsyncTask::new(IsSupportedTask)
}

// ---------------------------------------------------------------------------------------------
// createKey(name): make a new RSA-2048 key in Windows Hello. Windows shows a Hello prompt.
// Returns the public key as DER SubjectPublicKeyInfo. Fails if a key with this name exists.

pub struct CreateKeyTask {
    name: String,
}
impl Task for CreateKeyTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;
    fn compute(&mut self) -> Result<Vec<u8>> {
        ensure_apartment();
        help_prompt_to_front();
        let op = KeyCredentialManager::RequestCreateAsync(&HSTRING::from(self.name.as_str()), KeyCredentialCreationOption::FailIfExists)
            .map_err(|e| win_err("RequestCreateAsync", e))?;
        let res = op.join().map_err(|e| win_err("RequestCreateAsync", e))?;
        let status = res.Status().map_err(|e| win_err("Status", e))?;
        if status != KeyCredentialStatus::Success {
            return Err(hello_err(status_code(status), "Windows Hello did not make the key"));
        }
        let cred = res.Credential().map_err(|e| win_err("Credential", e))?;
        public_key_spki(&cred)
    }
    fn resolve(&mut self, _env: Env, out: Vec<u8>) -> Result<Buffer> {
        Ok(out.into())
    }
}

#[napi]
pub fn create_key(name: String) -> AsyncTask<CreateKeyTask> {
    AsyncTask::new(CreateKeyTask { name })
}

// ---------------------------------------------------------------------------------------------
// publicKey(name): read the public key of an existing key. Usually no prompt.

pub struct PublicKeyTask {
    name: String,
}
impl Task for PublicKeyTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;
    fn compute(&mut self) -> Result<Vec<u8>> {
        ensure_apartment();
        let cred = open_credential(&self.name)?;
        public_key_spki(&cred)
    }
    fn resolve(&mut self, _env: Env, out: Vec<u8>) -> Result<Buffer> {
        Ok(out.into())
    }
}

#[napi]
pub fn public_key(name: String) -> AsyncTask<PublicKeyTask> {
    AsyncTask::new(PublicKeyTask { name })
}

// ---------------------------------------------------------------------------------------------
// sign(name, data): Windows shows a Hello prompt, then signs `data` with RSASSA-PKCS1-v1_5
// SHA-256 (Windows hashes the data itself). Returns the 256-byte signature.

pub struct SignTask {
    name: String,
    data: Vec<u8>,
}
impl Task for SignTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;
    fn compute(&mut self) -> Result<Vec<u8>> {
        ensure_apartment();
        let cred = open_credential(&self.name)?;
        let input = CryptographicBuffer::CreateFromByteArray(&self.data).map_err(|e| win_err("CreateFromByteArray", e))?;
        help_prompt_to_front();
        let op = cred.RequestSignAsync(&input).map_err(|e| win_err("RequestSignAsync", e))?;
        let res = op.join().map_err(|e| win_err("RequestSignAsync", e))?;
        let status = res.Status().map_err(|e| win_err("Status", e))?;
        if status != KeyCredentialStatus::Success {
            return Err(hello_err(status_code(status), "Windows Hello did not sign"));
        }
        let sig = res.Result().map_err(|e| win_err("Result", e))?;
        buffer_to_vec(&sig)
    }
    fn resolve(&mut self, _env: Env, out: Vec<u8>) -> Result<Buffer> {
        Ok(out.into())
    }
}

#[napi]
pub fn sign(name: String, data: Buffer) -> AsyncTask<SignTask> {
    AsyncTask::new(SignTask { name, data: data.to_vec() })
}

// ---------------------------------------------------------------------------------------------
// deleteKey(name): remove the key from Windows Hello.

pub struct DeleteKeyTask {
    name: String,
}
impl Task for DeleteKeyTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> Result<()> {
        ensure_apartment();
        let op = KeyCredentialManager::DeleteAsync(&HSTRING::from(self.name.as_str())).map_err(|e| win_err("DeleteAsync", e))?;
        op.join().map_err(|e| win_err("DeleteAsync", e))
    }
    fn resolve(&mut self, _env: Env, _out: ()) -> Result<()> {
        Ok(())
    }
}

#[napi]
pub fn delete_key(name: String) -> AsyncTask<DeleteKeyTask> {
    AsyncTask::new(DeleteKeyTask { name })
}

// ---------------------------------------------------------------------------------------------
// attestation(name): ask Windows whether the key is in a TPM.
// "success" = TPM-backed and attested; "not_supported" = no TPM attestation (Hello keeps the key
// in software); "temporary_failure" = Windows could not reach the attestation service right now.

pub struct AttestationTask {
    name: String,
}
impl Task for AttestationTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> Result<String> {
        ensure_apartment();
        let cred = open_credential(&self.name)?;
        let op = cred.GetAttestationAsync().map_err(|e| win_err("GetAttestationAsync", e))?;
        let res = op.join().map_err(|e| win_err("GetAttestationAsync", e))?;
        let status = res.Status().map_err(|e| win_err("Status", e))?;
        Ok(match status {
            KeyCredentialAttestationStatus::Success => "success",
            KeyCredentialAttestationStatus::NotSupported => "not_supported",
            KeyCredentialAttestationStatus::TemporaryFailure => "temporary_failure",
            _ => "unknown_error",
        }
        .to_string())
    }
    fn resolve(&mut self, _env: Env, out: String) -> Result<String> {
        Ok(out)
    }
}

#[napi]
pub fn attestation(name: String) -> AsyncTask<AttestationTask> {
    AsyncTask::new(AttestationTask { name })
}

// ---------------------------------------------------------------------------------------------
// ageConsentGroup(): what Windows says about this account's age group, if anything.
// Uses Windows.System.User.CheckUserAgeConsentGroupAsync for "Child" and "Minor".
// Each answer is one of: "not_enforced" (Windows has no age rule for this account, which is the
// usual answer for local accounts), "included", "not_included", "unknown", "ambiguous",
// or "error: <text>" when Windows refuses to answer (for example in unpackaged apps).

#[napi(object)]
pub struct AgeConsentAnswer {
    pub child: String,
    pub minor: String,
}

fn age_result_name(r: windows::System::UserAgeConsentResult) -> &'static str {
    use windows::System::UserAgeConsentResult as R;
    match r {
        R::NotEnforced => "not_enforced",
        R::Included => "included",
        R::NotIncluded => "not_included",
        R::Ambiguous => "ambiguous",
        _ => "unknown",
    }
}

fn check_age_group(group: windows::System::UserAgeConsentGroup) -> String {
    let run = || -> windows::core::Result<String> {
        let user = windows::System::User::GetDefault()?;
        let r = user.CheckUserAgeConsentGroupAsync(group)?.join()?;
        Ok(age_result_name(r).to_string())
    };
    match run() {
        Ok(s) => s,
        Err(e) => format!("error: {} (0x{:08X})", e.message(), e.code().0 as u32),
    }
}

pub struct AgeConsentTask;
impl Task for AgeConsentTask {
    type Output = AgeConsentAnswer;
    type JsValue = AgeConsentAnswer;
    fn compute(&mut self) -> Result<AgeConsentAnswer> {
        ensure_apartment();
        Ok(AgeConsentAnswer {
            child: check_age_group(windows::System::UserAgeConsentGroup::Child),
            minor: check_age_group(windows::System::UserAgeConsentGroup::Minor),
        })
    }
    fn resolve(&mut self, _env: Env, out: AgeConsentAnswer) -> Result<AgeConsentAnswer> {
        Ok(out)
    }
}

#[napi]
pub fn age_consent_group() -> AsyncTask<AgeConsentTask> {
    AsyncTask::new(AgeConsentTask)
}
