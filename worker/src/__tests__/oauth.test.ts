import { describe, it, expect, beforeEach } from 'vitest';
import { generateSecureRandom, constantTimeEqual, sha256, sha256Base64url } from '../security/utils';
import { generateCodeVerifier, generateCodeChallenge, validateCodeVerifier } from '../oauth/pkce';

describe('Security Utils', () => {
  describe('constantTimeEqual', () => {
    it('should return true for equal strings', () => {
      expect(constantTimeEqual('hello', 'hello')).toBe(true);
    });

    it('should return false for different strings', () => {
      expect(constantTimeEqual('hello', 'world')).toBe(false);
    });

    it('should return false for different length strings', () => {
      expect(constantTimeEqual('hello', 'hello world')).toBe(false);
    });
  });

  describe('generateSecureRandom', () => {
    it('should generate different values each time', () => {
      const val1 = generateSecureRandom();
      const val2 = generateSecureRandom();
      expect(val1).not.toBe(val2);
    });

    it('should generate base64url encoded strings', () => {
      const value = generateSecureRandom();
      // Base64url should not contain +, /, or =
      expect(value).not.toMatch(/[+/=]/);
    });
  });

  describe('sha256', () => {
    it('should generate consistent hash for same input', async () => {
      const hash1 = await sha256('test');
      const hash2 = await sha256('test');
      expect(hash1).toBe(hash2);
    });

    it('should generate different hash for different input', async () => {
      const hash1 = await sha256('test1');
      const hash2 = await sha256('test2');
      expect(hash1).not.toBe(hash2);
    });
  });
});

describe('PKCE', () => {
  describe('generateCodeVerifier', () => {
    it('should generate valid code verifier', () => {
      const verifier = generateCodeVerifier();
      expect(verifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
    });

    it('should generate different values each time', () => {
      const v1 = generateCodeVerifier();
      const v2 = generateCodeVerifier();
      expect(v1).not.toBe(v2);
    });
  });

  describe('generateCodeChallenge', () => {
    it('should generate valid S256 challenge', async () => {
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      
      // Should be base64url encoded
      expect(challenge).not.toMatch(/[+/=]/);
      
      // Should be 43 characters (256 bits base64url encoded)
      expect(challenge).toHaveLength(43);
    });
  });

  describe('validateCodeVerifier', () => {
    it('should validate correct verifier/challenge pair', async () => {
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      
      const isValid = await validateCodeVerifier(verifier, challenge, 'S256');
      expect(isValid).toBe(true);
    });

    it('should reject incorrect verifier', async () => {
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const wrongVerifier = generateCodeVerifier();
      
      const isValid = await validateCodeVerifier(wrongVerifier, challenge, 'S256');
      expect(isValid).toBe(false);
    });

    it('should reject plain method', async () => {
      const verifier = generateCodeVerifier();
      
      const isValid = await validateCodeVerifier(verifier, verifier, 'plain');
      expect(isValid).toBe(false);
    });
  });
});

describe('Token Hashing', () => {
  it('should hash tokens consistently', async () => {
    const token = 'test_token_12345';
    const hash1 = await sha256(token);
    const hash2 = await sha256(token);
    
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64); // SHA-256 produces 64 hex characters
  });

  it('should produce different hashes for different tokens', async () => {
    const token1 = 'test_token_12345';
    const token2 = 'test_token_67890';
    
    const hash1 = await sha256(token1);
    const hash2 = await sha256(token2);
    
    expect(hash1).not.toBe(hash2);
  });
});