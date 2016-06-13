using System;

namespace PasswordHashing
{
    class Program
    {
        private const string password = "p@ssword!";
        static void Main(string[] args)
        {

            var passwordSalt = CryptoService.GenerateSalt();
            var passwordHash = CryptoService.ComputeHash(password, passwordSalt);

            Console.WriteLine("PasswordResult:\n");
            Console.WriteLine($"Plain Password: {password} \n");
            Console.WriteLine($"PasswordHash: {Convert.ToBase64String(passwordHash)} \n");
            Console.WriteLine($"PasswordSalt: {Convert.ToBase64String(passwordSalt)} \n");

            Console.ReadLine();
        }
    }
}
