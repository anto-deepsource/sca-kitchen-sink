using Newtonsoft.Json;
using System.Drawing;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string maliciousJson = @"{
            '$type': 'System.Windows.Data.ObjectDataProvider, PresentationFramework',
            'MethodName': 'Start',
            'MethodParameters': {
                '$type': 'System.Collections.ArrayList',
                '$values': ['cmd', '/c calc.exe']
            },
            'ObjectInstance': {'$type': 'System.Diagnostics.Process'}
        }";

        try
        {
            var obj = JsonConvert.DeserializeObject(maliciousJson, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Deserialization failed: {ex.Message}");
        }

        try
        {
            string userProvidedPath = @"../../malicious.jpg";
            using (Image img = Image.FromFile(userProvidedPath))
            {
                img.Save("processed.jpg");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Image processing failed: {ex.Message}");
        }

        string userInput = new string('a', 100) + "!";
        string pattern = @"^(a+)+!$";
        try
        {
            var match = Regex.IsMatch(userInput, pattern);
            Console.WriteLine($"Regex match: {match}");
        }
        catch (RegexMatchTimeoutException ex)
        {
            Console.WriteLine($"Regex timeout: {ex.Message}");
        }

        string secretKey = "very-weak-secret-key-vulnerable-to-brute-force";
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(secretKey);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("id", "1") }),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = tokenHandler.WriteToken(token);

        try
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireExpirationTime = false,
                ValidateLifetime = false
            };

            var principal = tokenHandler.ValidateToken(jwtToken, validationParameters, out var validatedToken);
            Console.WriteLine("Token validated successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Token validation failed: {ex.Message}");
        }
    }
} 
