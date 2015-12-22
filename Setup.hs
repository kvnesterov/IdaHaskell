import           Data.Maybe
import           Distribution.PackageDescription
import           Distribution.Simple
import           Distribution.Simple.LocalBuildInfo
import           Distribution.Simple.Program
import           Distribution.Simple.Setup
import           Distribution.Verbosity
import           System.Directory                   (copyFile,
                                                     createDirectoryIfMissing,
                                                     doesDirectoryExist,
                                                     getHomeDirectory,
                                                     removeFile)
import           System.Environment                 (lookupEnv)
import           System.FilePath                    ((</>))

main :: IO ()
main = defaultMainWithHooks simpleUserHooks { buildHook = localBuildHook,
                                              instHook  = localInstHook,
                                              copyHook  = localCopyHook,
                                              regHook   = localRegHook }

logC :: String -> IO ()
logC s = putStrLn ("[*] " ++ s)

localBuildHook :: PackageDescription -> LocalBuildInfo -> UserHooks -> BuildFlags -> IO ()
localBuildHook desc buildInfo hooks flags = do
  let progs = withPrograms buildInfo
      ghcProgram' = fromJust (lookupProgram ghcProgram progs)
      ghc = runProgram normal ghcProgram'
      gccProgram' = fromJust (lookupProgram gccProgram progs)
      gcc = runProgram normal gccProgram'
      hsc2hsProgram' = fromJust (lookupProgram hsc2hsProgram progs)
      hsc2hs = runProgram normal hsc2hsProgram'
      includeDirs' = includeDirs $ libBuildInfo $ fromJust $ library desc
      libInfo =  libBuildInfo $ fromJust $ library desc
      ccOptions' = map ("-optc" ++) $ ccOptions libInfo
      cSources' = cSources libInfo
      modules = exposedModules $ fromJust $ library desc
      srcDir = head $ hsSourceDirs libInfo
      buildDir' = buildDir buildInfo
      extraLibDirs' = head $ extraLibDirs libInfo

  logC "Building IdaHaskell Plugin"
  createDirectoryIfMissing True buildDir'
  ghc $ ["-I" ++ head includeDirs', "-shared", "-o", buildDir' </> "IdaHaskell.plw",
         "-package", "ghc", "-package", "text", "-fPIC", "-odir", buildDir',
         srcDir </> "Ida.hs", srcDir </> "Cli.hs", "-lstdc++",
         extraLibDirs' </> "ida.a", srcDir </> "export.def"] ++
         cSources' ++ ccOptions'

  logC "Preprocessing UserApi"
  hsc2hs $ ["-c", "g++", "-I" ++ head includeDirs', srcDir </> "UserApi.hsc"]
            ++ ccOptions libInfo

  logC "Static check of UserApi"
  ghc $ ["-fno-code", srcDir </> "UserApi.hs"]

  return ()

-- Some ugly codes
findIdaDir :: IO String
findIdaDir = do
  userDefined <- lookupEnv "IDA_PATH"
  case userDefined of
    Just path -> return path
    Nothing -> do
      test1 <- doesDirectoryExist "C:/Program Files (x86)/IDA 6.8"
      if test1 then return "C:/Program Files (x86)/IDA 6.8"
        else do
          test2 <- doesDirectoryExist "C:/Program Files/IDA 6.8"
          if test1 then return "C:/Program Files/IDA 6.8"
            else error "Could not find Ida Pro path, try set IDA_PATH env var"

localCopyHook :: PackageDescription -> LocalBuildInfo -> UserHooks -> CopyFlags -> IO ()
localCopyHook desc buildInfo hooks flags = do
  logC "Try to find Ida Pro installation path"
  idaDir <- findIdaDir
  logC $ "Found Ida Pro installation at " ++ show idaDir
  homeDir <- getHomeDirectory
  let libInfo       = libBuildInfo $ fromJust $ library desc
      srcDir        = head $ hsSourceDirs libInfo
      idaPluginsDir = idaDir </> "plugins"
      buildDir'     = buildDir buildInfo

  logC "Installing IdaHaskell Plugin"
  copyFile (buildDir' </> "IdaHaskell.plw") (idaPluginsDir </> "IdaHaskell.plw")
  -- logC "Installing helpers library"
  -- copyFile (buildDir' </> "helpers.dll") (idaDir </> "helpers.dll")
  logC $ "Installing UserApi to " ++ homeDir
  copyFile (srcDir </> "UserApi.hs") (homeDir </> "UserApi.hs")
  return ()

localRegHook :: PackageDescription -> LocalBuildInfo -> UserHooks -> RegisterFlags -> IO ()
localRegHook desc buildInfo hooks flags = return ()

localInstHook :: PackageDescription -> LocalBuildInfo -> UserHooks -> InstallFlags -> IO ()
localInstHook desc buildInfo userHooks flags = do
  logC "Try to find Ida Pro installation path"
  idaDir <- findIdaDir
  logC $ "Found Ida Pro installation at " ++ show idaDir
  homeDir <- getHomeDirectory
  let libInfo       = libBuildInfo $ fromJust $ library desc
      srcDir        = head $ hsSourceDirs libInfo
      idaPluginsDir = idaDir </> "plugins"
      buildDir'     = buildDir buildInfo

  logC "Installing IdaHaskell Plugin"
  copyFile (buildDir' </> "IdaHaskell.plw") (idaPluginsDir </> "IdaHaskell.plw")
  -- logC "Installing helpers library"
  -- copyFile (buildDir' </> "helpers.dll") (idaPluginsDir </> "helpers.dll")
  logC $ "Installing UserApi to " ++ homeDir
  copyFile (srcDir </> "UserApi.hs") (homeDir </> "UserApi.hs")
  return ()
