/**
 * Words that name a secret, across languages. Used to catch `password=…` style
 * assignments and sensitive object keys in non-English codebases. Every entry is
 * identifier-shaped (no spaces) so it works as both a key name and an assignment
 * keyword. Structured secrets (API keys, JWTs, cards) are language-independent
 * and handled by their own detectors — this list is only for the word-based ones.
 */
export const SECRET_KEYWORDS: string[] = Array.from(
  new Set(
    [
      // English
      'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key', 'api-key',
      'access_key', 'access-key', 'accesskey', 'secret_key', 'client_secret',
      'private_key', 'privatekey', 'credential', 'credentials', 'auth_token', 'passphrase',
      // Spanish
      'contraseña', 'contrasena', 'clave', 'secreto', 'credencial',
      // Portuguese
      'senha', 'segredo', 'chave_secreta',
      // German
      'passwort', 'kennwort', 'geheimnis', 'geheim', 'schlüssel', 'schluessel', 'zugangsschlüssel',
      // French
      'motdepasse', 'mot_de_passe', 'motdepass', 'clé', 'clef', 'clésecrète', 'secret',
      // Italian
      'segreto', 'chiave', 'parolachiave', 'parola_chiave', 'credenziale',
      // Dutch
      'wachtwoord', 'geheim', 'sleutel',
      // Polish
      'hasło', 'haslo', 'tajne', 'klucz', 'poufne',
      // Czech / Slovak
      'heslo', 'tajný', 'tajne', 'klíč', 'klic',
      // Romanian
      'parolă', 'parola', 'secret', 'cheie',
      // Swedish / Norwegian / Danish
      'lösenord', 'losenord', 'passord', 'adgangskode', 'hemlig', 'nyckel',
      // Greek
      'κωδικός', 'μυστικό', 'κλειδί',
      // Russian
      'пароль', 'секрет', 'токен', 'ключ', 'секретныйключ',
      // Ukrainian
      'пароль', 'секрет', 'ключ', 'таємний',
      // Turkish
      'şifre', 'sifre', 'parola', 'gizli', 'anahtar', 'gizlianahtar',
      // Azerbaijani
      'şifrə', 'parol', 'gizli', 'açar', 'məxfi',
      // Persian
      'رمز', 'رمزعبور', 'گذرواژه', 'کلمهعبور', 'کلید', 'محرمانه',
      // Arabic
      'كلمةالمرور', 'كلمةالسر', 'سر', 'رمز', 'مفتاح', 'سري',
      // Hebrew
      'סיסמה', 'סוד', 'מפתח',
      // Chinese
      '密码', '密碼', '秘密', '令牌', '密钥', '私钥', '口令',
      // Japanese
      'パスワード', '秘密', 'トークン', '暗証番号', '合言葉',
      // Korean
      '비밀번호', '암호', '비밀', '토큰', '비밀키',
      // Hindi
      'पासवर्ड', 'गुप्त', 'कुंजी',
      // Indonesian / Malay
      'katasandi', 'kata_sandi', 'sandi', 'rahasia', 'rahsia', 'kunci',
      // Vietnamese
      'matkhau', 'mat_khau', 'bimat', 'khoa',
      // Thai
      'รหัสผ่าน', 'ความลับ',
    ].map((w) => w.toLowerCase()),
  ),
);

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Alternation of all keywords, longest first so `api_key` wins over any prefix. */
function keywordAlternation(): string {
  return [...SECRET_KEYWORDS]
    .sort((a, b) => b.length - a.length)
    .map(escapeRe)
    .join('|');
}

/** `password = value` / `密码: value` in any listed language. Unicode-aware. */
export function assignmentPattern(): RegExp {
  return new RegExp(`(?:${keywordAlternation()})["'\\s]*[:=]\\s*["']?([^\\s"',;]{4,})["']?`, 'giu');
}

/** Object keys that are sensitive by name, in any listed language. */
export const MULTILANG_KEY_SET: ReadonlySet<string> = new Set(SECRET_KEYWORDS);
