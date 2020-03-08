using Microsoft.EntityFrameworkCore.Migrations;

namespace DockerDemo.IdentityServer.Data.Migrations.IdentityServer.IdentityDb
{
    public partial class DemoUser : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                @"
INSERT INTO public.""AspNetUsers""
(
 	""Id"",
    ""UserName"",
    ""NormalizedUserName"",
    ""Email"",
    ""NormalizedEmail"",
    ""EmailConfirmed"",
    ""PasswordHash"",
    ""SecurityStamp"",
    ""ConcurrencyStamp"",
    ""PhoneNumber"",
    ""PhoneNumberConfirmed"",
    ""TwoFactorEnabled"",
    ""LockoutEnd"",
    ""LockoutEnabled"",
    ""AccessFailedCount""
) VALUES (
	'7E6B7746-F7AC-4B24-BBCE-9C3D2E072D40',
    'demo',
    'DEMO',
    'demo@mail.ru',
    'DEMO@MAIL.RU',
    true,
    'AQAAAAEAACcQAAAAEAoEPPTLejtJztiqalkrNPbdTBUXnmx3Wvd/3gGUXE5KyjsFQPg4nEZqFbVWfHLvVw==',
    '5FE43Z5ISUKWNFM6TEBGFRJC5QR67SXP',
    'f3efdce9-b40e-4332-9be5-b09e90345535',
    null,
    false,
    false,
    null,
    false,
    0
);");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"DELETE FROM public.""AspNetUsers"" WHERE Email='demo@mail.ru'");
        }
    }
}