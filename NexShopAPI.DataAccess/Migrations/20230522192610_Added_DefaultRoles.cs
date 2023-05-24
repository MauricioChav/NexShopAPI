using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace NexShopAPI.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class Added_DefaultRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "da50135e-1d3c-4392-ab44-d0bb2c6d8b2b", null, "Administrator", "ADMINISTRATOR" },
                    { "e882492f-7e34-4e78-a9c8-288417a9ee9c", null, "User", "USER" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "da50135e-1d3c-4392-ab44-d0bb2c6d8b2b");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "e882492f-7e34-4e78-a9c8-288417a9ee9c");
        }
    }
}
