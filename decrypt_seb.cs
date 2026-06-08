using System.Security.Cryptography.X509Certificates;
using DictObj = System.Collections.Generic.Dictionary<string, object>;

public static class Main
{
    // Prefixes
    private const int PREFIX_LENGTH = 4;
    private const int MULTIPART_LENGTH = 8;
    private const int CUSTOMHEADER_LENGTH = 4;
    private const string PUBLIC_KEY_HASH_MODE = "pkhs";
    private const string PUBLIC_SYMMETRIC_KEY_MODE = "phsk";
    private const string PASSWORD_MODE = "pswd";
    private const string PLAIN_DATA_MODE = "plnd";
    private const string PASSWORD_CONFIGURING_CLIENT_MODE = "pwcc";
    private const string UNENCRYPTED_MODE = "<?xm";
    private const string MULTIPART_MODE = "mphd";
    private const string CUSTOM_HEADER_MODE = "cmhd";

    // Public key hash identifier length
    private const int PUBLIC_KEY_HASH_LENGTH = 20;
    public static void main(string[] args)
    {
        string fileName;
        if (args.Length > 0)
        {
            fileName = args[0];
        }
        else
        {
            Console.Write("Enter the path to your .seb configuration file: ");
            fileName = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(fileName))
            {
                Console.WriteLine("Error: File path cannot be empty.");
                return;
            }
        }

        if (!System.IO.File.Exists(fileName))
        {
            Console.WriteLine($"Error: File '{fileName}' does not exist.");
            return;
        }

        bool forEditing = false;
        string filePassword = "";
        bool passwordIsHash = false;
        X509Certificate2 fileCertificateRef = null;
        try
        {
            var settings = SEBSettings.ReadSebConfigurationFile(fileName, forEditing, ref filePassword, ref passwordIsHash, ref fileCertificateRef);
            string outputFileName = fileName + ".new.seb";
            bool success = SEBSettings.WriteSebConfigurationFile(outputFileName, filePassword, passwordIsHash, fileCertificateRef, false, SEBSettings.sebConfigPurposes.sebConfigPurposeStartingExam, false);
            if (success)
            {
                Console.WriteLine("Successfully decoded and saved to: " + outputFileName);
                
                Console.WriteLine("\n--- SEB Configuration Security Keys ---");
                try
                {
                    string configKey = SEBProtectionController.ComputeConfigurationKey();
                    Console.WriteLine("Configuration Key (CK): " + configKey);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed to compute Configuration Key: " + ex.Message);
                }

                try
                {
                    string bek = SEBProtectionController.ComputeBrowserExamKey();
                    Console.WriteLine("Browser Exam Key (BEK) : " + bek);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed to compute Browser Exam Key: " + ex.Message);
                }
                Console.WriteLine("---------------------------------------\n");
            }
            else
            {
                Console.WriteLine("Failed to write decoded file.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("An error occurred: " + ex.Message);
        }
    }
}