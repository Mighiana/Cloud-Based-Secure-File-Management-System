FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY SecureFileUploadPortal/SecureFileUploadPortal.csproj SecureFileUploadPortal/
RUN dotnet restore SecureFileUploadPortal/SecureFileUploadPortal.csproj
COPY SecureFileUploadPortal/ SecureFileUploadPortal/
RUN dotnet publish SecureFileUploadPortal/SecureFileUploadPortal.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
RUN mkdir /keys && chown app /keys
USER app
ENTRYPOINT ["dotnet", "SecureFileUploadPortal.dll"]
