# dotnet-8-role-based-authorization-api

.NET 8.0 - Role Based Authorization API and Jason Web Tokens Authentication

## How to setup the project :

1 - Have both .NET 8.0 SDK and Docker installed

2 - install MSSQL SERVER 2022 with these commands

(get the official MSSQL SERVER image)
	
`docker pull mcr.microsoft.com/mssql/server:2022-latest`
	
(run the container)

`docker run -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=<YourStrong@Passw0rd>" -p 1433:1433 --name mssql1 --hostname mssql1 -d mcr.microsoft.com/mssql/server:2022-latest`

3 - add initial migrations
	
`dotnet ef migrations add <NameOfYourMigration>`

(example):
	
`dotnet ef migrations add InitialMigration`

4 - apply the added migrations

`dotnet ef database update`