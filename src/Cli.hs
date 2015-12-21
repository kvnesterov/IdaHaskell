{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Cli
       (doInitSession,
        evalString,
        Session(..))
       where

import           Control.Applicative
import           DynFlags
import           GHC
import           GHC.Paths
import           GhcMonad            (liftIO)
    -- liftIO from Control.Monad.IO.Class
import           Control.Concurrent
import           Control.Monad

import           ErrUtils
import           Exception
import           MonadUtils
import           Panic
import           System.IO.Unsafe
import           Unsafe.Coerce

import           Data.Char
import           Data.List
import           Data.Maybe
import qualified Data.Text           as T

import           Debugger
import           Outputable

import           Foreign.Ptr         (Ptr)
import           ObjLink

type Session = Either String HscEnv

customErrorHandler :: (ExceptionMonad m, MonadIO m)
                   => m a -> m (Either String a)
customErrorHandler m = do
  ghandle (\(ex :: SomeException) -> return (Left (show ex))) $
    handleGhcException (\ge -> return (Left (showGhcException ge "\n"))) $
    -- flip gfinally (liftIO $ print "qweqwe") $
    m >>= return . Right

doInitSession :: IO (Either String HscEnv)
doInitSession =
  -- defaultErrorHandler defaultFatalMessager defaultFlushOut $
  customErrorHandler $
  runGhc (Just libdir) $ do
    dflags'' <- getSessionDynFlags
    let dflags' = foldr (flip gopt_unset) dflags'' [Opt_GhciSandbox]
        dflags  = foldr (flip gopt_set) dflags' [ Opt_PrintExplicitForalls
                                                , Opt_PrintExplicitKinds
                                                , Opt_PrintBindResult
                                                -- , Opt_BreakOnException
                                                -- , Opt_BreakOnError
                                                , Opt_PrintEvldWithShow
                                                ]
    setSessionDynFlags $ dflags { hscTarget = HscInterpreted
                                , ghcLink   = LinkInMemory
                                }
    -- setTargets =<< sequence [ guessTarget "Module Main where asd = 1" Nothing ]
    load LoadAllTargets
    setContext [
      -- IIModule $ mkModuleName "Main",
      IIDecl . simpleImportDecl . mkModuleName $ "Control.Monad",
      IIDecl . simpleImportDecl . mkModuleName $  "Prelude"]

    session <- getSession
    return session

addImportToContext :: GhcMonad m => HscEnv -> String -> m HscEnv
addImportToContext session str = do
  setSession session
  idecl <- GHC.parseImportDecl ("import " ++  str)
  currContext <- getContext
  setContext ((IIDecl idecl):currContext)
  getSession >>= return

addImportPath :: GhcMonad m => HscEnv -> String -> m HscEnv
addImportPath session path = do
  setSession session
  dflags <- getSessionDynFlags
  setSessionDynFlags $ dflags { importPaths = (path:(importPaths dflags)) }

  dflags <- getSessionDynFlags

  getSession >>= return

addModule :: GhcMonad m => HscEnv -> String -> m HscEnv
addModule session paths = do
  setSession session
  let files = map T.unpack $ T.splitOn " " $ T.pack paths
  targets <- mapM (\m -> GHC.guessTarget m Nothing) files

  currContext <- getContext
  mapM_ GHC.removeTarget [ tid | Target tid _ _ <- targets ]
  mapM_ GHC.addTarget targets
  load LoadAllTargets

  setContext currContext

  getSession >>= return

showModules :: GhcMonad m => HscEnv -> String -> m HscEnv
showModules session str = do
  setSession session
  loaded_mods <- getLoadedModules
  let show_one ms = do m <- showModule ms; liftIO (putStrLn m)
  mapM_ show_one loaded_mods
  getSession >>= return

getLoadedModules :: GhcMonad m => m [ModSummary]
getLoadedModules = do
  graph <- GHC.getModuleGraph
  filterM (GHC.isLoaded . GHC.ms_mod_name) graph

loadDLL' :: GhcMonad m => HscEnv -> String -> m HscEnv
loadDLL' session str = do
  setSession session
  liftIO $ loadDLL str
  getSession >>= return

loadObj' :: GhcMonad m => HscEnv -> String -> m HscEnv
loadObj' session str = do
  setSession session
  liftIO $ loadObj str
  getSession >>= return

specCommands :: GhcMonad m => [(String, HscEnv -> String -> m HscEnv)]
specCommands = [
  ("import", addImportToContext)
  , ("addPath", addImportPath)
  , ("addMod", addModule)
  , ("showModules", showModules)
  , ("loadDLL", loadDLL')
  , ("loadObj", loadObj')
  ]

lookupCommand :: GhcMonad m => String -> Maybe (String, (HscEnv -> String -> m HscEnv))
lookupCommand str = do
  let lookupPrefix s = find $ (s `isPrefixOf`) . fst
  lookupPrefix str specCommands >>= return

evalSpecCommand :: HscEnv -> String -> IO (Either String HscEnv)
evalSpecCommand session str =
  customErrorHandler $
  runGhc (Just libdir) $ do
    let (cmd, rest) = break isSpace str
    setSession session
    case lookupCommand cmd of
     Nothing -> do
       liftIO $ print ("unknown command " ++ str ++ "\n")
       error ("unknown command " ++ str ++ "\n")
     Just e -> do
       liftIO $ print $ fst e
       newSession <- (snd $ e) session (dropWhile isSpace rest)
       return newSession

evalString :: HscEnv -> (String -> IO()) -> String -> IO (Either String HscEnv)
evalString session _ s | (':' : cmd) <- s = evalSpecCommand session cmd
evalString session printFunc s =
  customErrorHandler $
  runGhc (Just libdir) $ do
    setSession session

    act <- runStmt s RunToCompletion
    case act of
     RunOk ns -> do
       mapM_ (\n -> do
                 mty <- lookupName n
                 case mty of
                  Just (AnId aid) -> do
                    df <- getSessionDynFlags
                    t <- obtainTermFromId maxBound True aid
                    sdoc <- showTerm t
                    liftIO $ printFunc ((showSDoc df sdoc) ++ "\n")
                    return ()
                 return ())
         ns
     _ -> return ()

    session <- getSession
    return session
