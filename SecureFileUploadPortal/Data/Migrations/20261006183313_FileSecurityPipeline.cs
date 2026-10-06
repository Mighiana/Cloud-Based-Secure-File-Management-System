using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecureFileUploadPortal.Data.Migrations
{
    /// <inheritdoc />
    public partial class FileSecurityPipeline : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "ConcurrencyStamp",
                table: "Files",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<DateTime>(
                name: "NextAttemptAtUtc",
                table: "Files",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ScanEngine",
                table: "Files",
                type: "nvarchar(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Sha256",
                table: "Files",
                type: "char(64)",
                unicode: false,
                fixedLength: true,
                maxLength: 64,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Status",
                table: "Files",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "Quarantined");

            migrationBuilder.AddColumn<string>(
                name: "StatusReason",
                table: "Files",
                type: "nvarchar(500)",
                maxLength: 500,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "StorageArea",
                table: "Files",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "Quarantine");

            migrationBuilder.AddColumn<DateTime>(
                name: "ValidatedAtUtc",
                table: "Files",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ValidationAttempts",
                table: "Files",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "ValidationStartedAtUtc",
                table: "Files",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "EntryHash",
                table: "AuditLogs",
                type: "varchar(64)",
                unicode: false,
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "FileId",
                table: "AuditLogs",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PreviousHash",
                table: "AuditLogs",
                type: "varchar(64)",
                unicode: false,
                maxLength: 64,
                nullable: true);

            // Files uploaded before the pipeline existed were never validated: keep them out of the download path.
            migrationBuilder.Sql(
                "UPDATE Files SET StatusReason = 'uploaded before the validation pipeline existed; not validated', ConcurrencyStamp = NEWID()");

            migrationBuilder.CreateIndex(
                name: "IX_Files_Sha256",
                table: "Files",
                column: "Sha256");

            migrationBuilder.CreateIndex(
                name: "IX_Files_Status_NextAttemptAtUtc",
                table: "Files",
                columns: new[] { "Status", "NextAttemptAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_FileId",
                table: "AuditLogs",
                column: "FileId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Files_Sha256",
                table: "Files");

            migrationBuilder.DropIndex(
                name: "IX_Files_Status_NextAttemptAtUtc",
                table: "Files");

            migrationBuilder.DropIndex(
                name: "IX_AuditLogs_FileId",
                table: "AuditLogs");

            migrationBuilder.DropColumn(
                name: "ConcurrencyStamp",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "NextAttemptAtUtc",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "ScanEngine",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "Sha256",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "Status",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "StatusReason",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "StorageArea",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "ValidatedAtUtc",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "ValidationAttempts",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "ValidationStartedAtUtc",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "EntryHash",
                table: "AuditLogs");

            migrationBuilder.DropColumn(
                name: "FileId",
                table: "AuditLogs");

            migrationBuilder.DropColumn(
                name: "PreviousHash",
                table: "AuditLogs");
        }
    }
}
