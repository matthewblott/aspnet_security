namespace aspnet_security
{
  using System;
  using System.Collections.Generic;
  using System.Security.Cryptography;
  using Microsoft.AspNetCore.Cryptography.KeyDerivation;
  
  public static class PasswordHasher
  {
    private const int IterCount = 10000;

    public static string HashPassword(string password)
    {
      static void WriteNetworkByteOrder(IList<byte> buffer, int offset, uint value)
      {
        buffer[offset + 0] = (byte) (value >> 24);
        buffer[offset + 1] = (byte) (value >> 16);
        buffer[offset + 2] = (byte) (value >> 8);
        buffer[offset + 3] = (byte) (value >> 0);
      }
      
      const int saltSize = 128 / 8;
      const int numBytesRequested = 256 / 8;
      
      var salt = new byte[saltSize];
      
      RandomNumberGenerator.Create().GetBytes(salt);
      
      var subKey = KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA256, IterCount, numBytesRequested);
      var outputBytes = new byte[13 + salt.Length + subKey.Length];
      
      outputBytes[0] = 0x01; // format marker
      
      WriteNetworkByteOrder(outputBytes, 1, (uint) KeyDerivationPrf.HMACSHA256);
      WriteNetworkByteOrder(outputBytes, 5, IterCount);
      WriteNetworkByteOrder(outputBytes, 9, saltSize);
      
      Buffer.BlockCopy(salt, 0, outputBytes, 13, salt.Length);
      Buffer.BlockCopy(subKey, 0, outputBytes, 13 + saltSize, subKey.Length);

      var base64String = Convert.ToBase64String(outputBytes);

      return base64String;
      
    }

    public static bool VerifyHashedPassword(string hashedPassword, string password)
    {
      static uint ReadNetworkByteOrder(IReadOnlyList<byte> buffer, int offset) 
        => ((uint) buffer[offset + 0] << 24)
           | ((uint) buffer[offset + 1] << 16)
           | ((uint) buffer[offset + 2] << 8)
           | buffer[offset + 3];
      
      try
      {
        var bytes = Convert.FromBase64String(hashedPassword);
        var prf = (KeyDerivationPrf) ReadNetworkByteOrder(bytes, 1);
        var iterCount = (int) ReadNetworkByteOrder(bytes, 5);

        if (iterCount < IterCount)
        {
          return false;
        }
        
        var saltLength = (int) ReadNetworkByteOrder(bytes, 9);

        if (saltLength < 128 / 8)
        {
          return false;
        }

        var salt = new byte[saltLength];
        Buffer.BlockCopy(bytes, 13, salt, 0, salt.Length);

        var subKeyLength = bytes.Length - 13 - salt.Length;
        
        if (subKeyLength < 128 / 8)
        {
          return false;
        }

        var expectedSubKey = new byte[subKeyLength];
        
        Buffer.BlockCopy(bytes, 13 + salt.Length, expectedSubKey, 0, expectedSubKey.Length);

        var actualSubKey = KeyDerivation.Pbkdf2(password, salt, prf, iterCount, subKeyLength);
        
        return CryptographicOperations.FixedTimeEquals(actualSubKey, expectedSubKey);
        
      }
      catch
      {
        return false;
      }
      
    }
    
  }

}