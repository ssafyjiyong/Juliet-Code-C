@echo off
SET "SPARROW_HOME=%~dp0"
SET "WHISTLE_HOME=%SPARROW_HOME%whistle"
SET "SPARROW_CONF=%SPARROW_HOME%sparrow.properties"
SET "POLICY=%WHISTLE_HOME%\conf\policy"

SET ARGS=%*
IF NOT '%1' == '' (
  SET ARGS=%ARGS:\"=\\"%
)

SET _JAVAPATH=
IF EXIST "%SPARROW_HOME%jre" (
  SET "_JAVAPATH=%SPARROW_HOME%jre\bin\"
)
IF NOT EXIST "%SPARROW_HOME%logs" (
  mkdir "%SPARROW_HOME%logs"
)

IF NOT EXIST "%SPARROW_HOME%sparrow.properties" (
  echo Not exist [sparrow.properties]. Please setup first.
  pause
  GOTO :EOF
)

"%_JAVAPATH%java" -Dsparrow.home="%SPARROW_HOME%\" -Dlogback.configurationFile="%WHISTLE_HOME%\conf\logback-update.xml" -Dsparrow.configuration="%SPARROW_CONF%" -jar "%WHISTLE_HOME%\update\update.jar" %ARGS%

IF EXIST "%SPARROW_HOME%err_update" (
  IF "%~1" == "SPARROW_GUI" (
    echo.
    echo Update Failed. Check Server connection.
    echo.
	pause
  )
  GOTO :EOF
)
SET "CLASSPATH=%JAVA_HOME%\lib\tools.jar;%WHISTLE_HOME%\lib\*;"
FOR /D %%a in ("%SPARROW_HOME%module\*") DO (
  IF EXIST "%%a\target\classes" (
    CALL :AddToPath %%a\target\classes
  )
)

IF "%~1" == "SPARROW_GUI" (
  start /b "" "%_JAVAPATH%javaw" -Xmx1024m -cp "%CLASSPATH%;" -Dsparrow.home="%SPARROW_HOME%\" -Djava.security.policy="%POLICY%" -Dlogback.configurationFile="%LOG_CONF%" -Dsparrow.configuration="%SPARROW_CONF%" %CLASSNAME% %ARGS% 
) ELSE (
  "%_JAVAPATH%java" -Xmx1024m -cp "%CLASSPATH%;" -Dsparrow.home="%SPARROW_HOME%\" -Djava.security.policy="%POLICY%" -Dlogging.config="%LOG_CONF%" -Dlogback.configurationFile="%LOG_CONF%" -Dsparrow.configuration="%SPARROW_CONF%" %CLASSNAME% %ARGS% 
)

GOTO :EOF

:AddToPath
SET MODULE_PATH=%1
SET MODULE_PATH=%MODULE_PATH:vcs=x%
SET CLASSPATH=%MODULE_PATH%;%CLASSPATH%
GOTO :EOF

:EOF

