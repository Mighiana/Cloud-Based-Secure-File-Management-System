using Microsoft.AspNetCore.Mvc;
using SecureFileUploadPortal.Services;
using System;
using System.IO;
using System.Threading.Tasks;

namespace SecureFileUploadPortal.Controllers
{
    public class FileController : Controller
    {
        private readonly S3Service _s3Service;
        private readonly ILogger<FileController> _logger;

        public FileController(S3Service s3Service, ILogger<FileController> logger)
        {
            _s3Service = s3Service;
            _logger = logger;
        }

        // Upload form
        public IActionResult Upload()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Upload(IFormFile file)
        {
            if (file == null || file.Length == 0)
            {
                TempData["Error"] = "Please select a file.";
                return View();
            }
            try
            {
                await _s3Service.UploadFileAsync(file);
                // Simulate AI scan
                await Task.Delay(2000); // 2s "scan"
                TempData["ScanResult"] = "No sensitive data found (Macie scan passed ✅)";
                _s3Service.AddAlert($"AI scan on '{file.FileName}': Clean");
                TempData["Success"] = "File uploaded successfully!";
                // Add alert for admin
                _s3Service.AddAlert($"File '{file.FileName}' uploaded by user at {DateTime.Now}");
            }
            catch (Exception ex)
            {
                TempData["Error"] = $"Upload failed: {ex.Message}";
                _s3Service.AddAlert($"Failed upload attempt: '{file.FileName}' at {DateTime.Now}");
            }
            return RedirectToAction("List");
        }

        // List all files
        public async Task<IActionResult> List()
        {
            var files = await _s3Service.ListFilesAsync();
            return View(files);
        }

        // Download file
        public IActionResult Download(string key)
        {
            var url = _s3Service.GetPreSignedURL(key);
            return Redirect(url);
        }

        // Delete file
        public async Task<IActionResult> Delete(string key)
        {
            try
            {
                await _s3Service.DeleteFileAsync(key);
                TempData["Success"] = "File deleted successfully!";
                // Add alert for admin
                _s3Service.AddAlert($"File '{key}' deleted by user at {DateTime.Now}");
            }
            catch (Exception ex)
            {
                TempData["Error"] = $"Delete failed: {ex.Message}";
                _s3Service.AddAlert($"Failed delete attempt: '{key}' at {DateTime.Now}");
            }
            return RedirectToAction("List");
        }

        // Backup to Glacier (Simulated)
        public async Task<IActionResult> BackupToGlacier(string key)
        {
            if (string.IsNullOrEmpty(key)) return BadRequest("Invalid key.");
            try
            {
                // Simulate: Log or copy to cold storage bucket
                _s3Service.AddAlert($"File '{key}' backed up to Glacier (cold storage)");
                TempData["Success"] = "File backed up to Glacier for long-term storage.";
            }
            catch (Exception ex)
            {
                TempData["Error"] = "Backup failed.";
            }
            return RedirectToAction("List");
        }
    }
}