{-# LANGUAGE ForeignFunctionInterface #-}
module Ida where

import           Cli
import           Control.Concurrent
import           Control.Monad
import           Foreign
import           Foreign.C.String
import           Foreign.C.Types
import           Foreign.Ptr
import           Foreign.Storable
import           GHC.IO.Handle          (hDuplicate, hDuplicateTo)
import           System.Directory       (getHomeDirectory,
                                         getTemporaryDirectory)
import           System.FilePath        ((</>))
import           System.IO

import           Control.Monad.IO.Class
import           Data.IORef
import           System.IO.Unsafe


-- foreign export ccall h_msg :: IO (CString -> IO ())
foreign export ccall h_ida_init :: IO ()
foreign export ccall h_ida_term :: IO ()
foreign export ccall h_ida_run  :: CInt -> IO ()
foreign export ccall h_cli_execute_line :: CString -> IO Bool

type Msg = Int -> CString -> IO ()
foreign import ccall "dynamic"
  getMsg :: FunPtr Msg -> Msg
foreign import ccall "&callui" callui :: Ptr IntPtr

globalSession :: IORef Session
{-# NOINLINE globalSession #-}
globalSession = unsafePerformIO (newIORef $ unsafePerformIO $ doInitSession)

-- Ida plugin callback
-----------------------------------------------------

h_ida_init = do
  tmpDir <- getTemporaryDirectory
  (_, stdoutNew) <- openTempFile tmpDir "ida_stdout"
  (_, stderrNew) <- openTempFile tmpDir "ida_stderr"
  hDuplicateTo stdoutNew stdout
  hDuplicateTo stderrNew stderr

  initCLI

  h_msg "Release the Kraken!\n"

  return ()

h_ida_run arg = do
  h_msg "Kraken is ready to serve.\n"
  h_msg ("...but he does not know what to do with " ++
    (show arg))
  return ()

h_ida_term = do
  h_msg "Kraken is going home...\n"
  return ()
-----------------------------------------------------

h_cli_execute_line :: CString -> IO (Bool)
h_cli_execute_line s = do
  -- h_msg "h_cli_execute_line\n"
  line <- peekCString s
  -- session <- join $ takeMVar hSession
  -- ret <- doInitSession
  ret <- readIORef globalSession

  case ret of
   Left err -> h_msg err
   Right session -> do
     ret <- evalString session h_msg line
     case ret of
      Left err -> h_msg err
      Right session -> do
        writeIORef globalSession (Right session)
        return ()
     -- return ()
  -- h_msg (line ++ "\n")
  return (True)

h_msg :: String -> IO ()
h_msg s = do
  addr <- peek callui
  let f = getMsg $ castPtrToFunPtr $ intPtrToPtr addr
  withCString s (\x -> f 23 x)
  return ()

executeLine s = do
  ret <- readIORef globalSession

  case ret of
   Left err -> h_msg err
   Right session -> do
     ret <- evalString session h_msg s
     case ret of
      Left err -> h_msg err
      Right session -> do
        writeIORef globalSession (Right session)
        return ()
  return (True)

initCLI = do
  h_msg "Loading ida.wll...\n"
  executeLine ":loadDLL ida.wll"
  h_msg "Loading IdaHaskell.plw...\n"
  executeLine ":loadDLL IdaHaskell.plw"
  -- h_msg "Loading helpers library...\n"
  -- executeLine ":loadDLL helpers.dll"
  h_msg "Loading ~/UserApi.hs...\n"
  homeDir <- getHomeDirectory
  executeLine (":addMod " ++ (homeDir </> "UserApi.hs"))
  executeLine ":import UserApi"
  h_msg "Init UserApi...\n"
  executeLine "run"

  return ()
