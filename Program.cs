namespace aspnet_security
{
  using System;
  
  internal static class Program
  {
    private static void Main(string[] args)
    {
      Console.WriteLine("Enter a password");

      var password = Console.ReadLine();
      var hashedPassword = PasswordHasher.HashPassword(password);
      
      Console.WriteLine("Your hashed password is:");
      Console.WriteLine(hashedPassword);
      Console.WriteLine("Re-enter your password to confirm");

      var passwordConfirm = Console.ReadLine();

      var isValidPassword = PasswordHasher.VerifyHashedPassword(hashedPassword, passwordConfirm);

      Console.WriteLine(isValidPassword ? "Yay, password successful :-)" : "Boo! Invalid password :-(");
      Console.WriteLine("Press any key to exit ...");
      Console.Read();

    }
    
  }
  
}