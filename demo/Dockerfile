FROM microsoft/aspnetcore-build:2.0 AS build-env
COPY ./MiraclAuthentication.Core2.0 ./MiraclAuthentication.Core2.0
COPY ./demo ./demo
WORKDIR /demo
RUN dotnet restore --verbosity quiet
RUN dotnet publish -c Release -o out

FROM microsoft/aspnetcore:2.0
WORKDIR /demo
COPY --from=build-env /demo/out .
ENTRYPOINT ["dotnet", "demo.dll"]
