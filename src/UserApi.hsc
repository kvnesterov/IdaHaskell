{-# LANGUAGE CPP                      #-}
{-# LANGUAGE ForeignFunctionInterface #-}

#include <ida.hpp>
#include <ua.hpp>
#include <funcs.hpp>
#include <nalt.hpp>
#include <bytes.hpp>
#include <gdl.hpp>

module UserApi
    ( msg
      , jumpto
      , here
      , qword
      , dword
      , word
      , byte
      , patchDword
      , patchWord
      , patchByte
      , getString
      , getCString
      , getUString
      , getMnem
      , Insn(..)
      , OpType(..)
      , getCmd
      , hex
      , setIdcFunc
      , addHotKey
      , delHotKey
      , wrapCallback
      , getImagebase
      , getInputFileName
      , getComment
      , setComment
      , run
      , rel
      , relHere
      , getFuncQty
      , getNFunc
      , getFunc
      , funcContains
      , getFuncNum
      , getPrevFunc
      , getNextFunc
      , getFuncLimits
      , getNextFuncAddr
      , getFuncItemsEA
      , getFuncItems
      , getFuncAsm
      , msgLn
      , flowChartCreate
      , flowChartRelease
      , flowChartGetBlock
      , flowChartForFunc
    ) where

import           Data.Int
import           Data.Word
import           Foreign
import           Foreign.C.String
import           Foreign.C.Types
import           Foreign.Ptr
import           Foreign.Storable
import           Numeric

import           Control.Monad
import           Control.Applicative
import           Control.Monad.IO.Class (liftIO)
import           Data.Char              (isLetter)
import           Data.Hashable          (hash)
import           Data.List
import           Data.Maybe

import           System.FilePath

#ifdef BIT64
type EA  = Word64
type CEA = CEA Int64
#else
type EA  = Word32
type CEA = CUInt
#endif

maxStr :: Int
maxStr = 0x400



type AddHotkey = Int -> CString -> CString -> IO ()
foreign import ccall "dynamic"
  cast2AddHotkey :: FunPtr AddHotkey -> AddHotkey
type DelHotkey = Int -> CString -> IO (CUChar)
foreign import ccall "dynamic"
  cast2DelHotkey :: FunPtr DelHotkey -> DelHotkey
type Here = Int -> Ptr CInt -> IO Int
foreign import ccall "dynamic"
  cast2Here :: FunPtr Here -> Here
type Jumpto = Int -> EA -> Int -> Int -> IO ()
foreign import ccall "dynamic"
  cast2Jumpto :: FunPtr Jumpto -> Jumpto
type Msg = Int -> CString -> IO ()
foreign import ccall "dynamic"
  cast2Msg :: FunPtr Msg -> Msg
foreign import ccall "&callui" callui :: Ptr IntPtr

---------------------------------------------------------------------
--                            Helpers
cui i = CUInt $ fromIntegral i
ci i  = CInt $ fromIntegral i
hex x = (++) "0x" $ showHex x ""

wrapCallback :: CallbackWrap
wrapCallback f args res = do
  f ()
  return $ cui 0

rel :: EA -> IO String
rel offset = liftM (hex . (+ offset)) $ here

---------------------------------------------------------------------

msg :: Show a => a -> IO ()
msg = msgC . show

msgLn :: Show a => a -> IO ()
msgLn s = msgC $ show s ++ "\n"

msgC :: String -> IO ()
msgC s = do
  addr <- peek callui
  let f = cast2Msg $ castPtrToFunPtr $ intPtrToPtr addr
  withCString s $ f 23
  return ()

jumpto :: EA -> IO ()
jumpto ea = do
  addr <- peek callui
  let f = cast2Jumpto $ castPtrToFunPtr $ intPtrToPtr addr
  f 139 ea (-1) 1
  return ()

here :: IO EA
here = do
  addr <- peek callui
  let f = cast2Here $ castPtrToFunPtr $ intPtrToPtr addr
  r <- alloca $ \ea -> do
    f 10 ea
    peek ea
  return (fromIntegral r)

addHotKey :: String -> Callback -> IO Bool
addHotKey hotkey callback = do
  addr <- peek callui
  let f = cast2AddHotkey $ castPtrToFunPtr $ intPtrToPtr addr
      fName = "lambda_" ++ show (hash hotkey)
  r <- setIdcFunc fName callback
  if r then
    withCString hotkey $
    \h ->
     withCString fName $
     \ n -> do
            f (#const ui_add_idckey) h n
            return True
    else return False

delHotKey :: String -> IO Bool
delHotKey hotkey = do
  addr <- peek callui
  let f = cast2DelHotkey $ castPtrToFunPtr $ intPtrToPtr addr
  withCString hotkey $
    \h -> do
      r <- f (#const ui_del_idckey) h
      msgLn r
      if r /= 0 then return True
        else return False


 -- Get one qword (64-bit) of the program at 'ea'
 -- This function takes into account order of bytes specified in inf.mf
 -- This function works only for 8bit byte processors.
foreign import ccall "get_qword" get_qword :: CUInt -> IO CULong
qword :: EA -> IO Word64
qword ea = do
  d <- get_qword $ CUInt ea
  return $ fromIntegral d

 -- Get two wide words (4 'bytes') of the program at 'ea'
 -- Some processors may access more than 8bit quantity at an address.
 -- These processors have 32-bit byte organization from the IDA's point of view.
 -- This function takes into account order of bytes specified in inf.mf
 -- Note: this function works incorrectly if ph.nbits > 16
foreign import ccall "get_full_long" get_full_long :: CUInt -> IO CUInt
dword :: EA -> IO Word32
dword ea = do
  d <- get_full_long $ CUInt ea
  return $ fromIntegral d

 -- Get one wide word (2 'byte') of the program at 'ea'
 -- Some processors may access more than 8bit quantity at an address.
 -- These processors have 32-bit byte organization from the IDA's point of view.
 -- This function takes into account order of bytes specified in inf.mf
foreign import ccall "get_full_word" get_full_word :: CUInt -> IO CUShort
word :: EA -> IO Word16
word ea = do
  d <- get_full_word $ CUInt ea
  return $ fromIntegral d

 -- Get one wide byte of the program at 'ea'
 -- Some processors may access more than 8bit quantity at an address.
 -- These processors have 32-bit byte organization from the IDA's point of view.
foreign import ccall "get_full_byte" get_full_byte :: CUInt -> IO CUChar
byte :: EA -> IO Word8
byte ea = do
  d <- get_full_byte $ CUInt ea
  return $ fromIntegral d

 -- Patch a dword of the program. The original value of the dword is saved
 -- and can be obtained by get_original_long() function.
 -- This function DOESN'T work for wide byte processors.
 -- This function takes into account order of bytes specified in inf.mf
foreign import ccall "patch_long" patch_long :: CUInt -> CULong -> IO CUChar
patchDword :: EA -> Word32 -> IO Word8
patchDword ea val = do
  d <- patch_long (CUInt ea) (CULong $ fromIntegral val)
  return $ fromIntegral d

 -- Patch a word of the program. The original value of the word is saved
 -- and can be obtained by get_original_word() function.
 -- This function works for wide byte processors too.
 -- This function takes into account order of bytes specified in inf.mf
foreign import ccall "patch_word" patch_word :: CUInt -> CULong -> IO CUChar
patchWord :: EA -> Word16 -> IO Word8
patchWord ea val = do
  d <- patch_word (CUInt ea) (CULong $ fromIntegral val)
  return $ fromIntegral d

 -- Patch a byte of the program. The original value of the byte is saved
 -- and can be obtained by get_original_byte() function.
 -- This function works for wide byte processors too.
 -- returns: true-the database has been modified
foreign import ccall "patch_byte" patch_byte :: CUInt -> CUInt -> IO CUChar
patchByte :: EA -> Word8 -> IO Word8
patchByte ea val = do
  d <- patch_byte (CUInt ea) (CUInt $ fromIntegral val)
  return $ fromIntegral d

 -- Get contents of ascii string
 -- This function returns the displayed part of the string
 -- It works even if the string has not been created in the database yet.
 --      ea       - linear address of the string
 --      len      - length of the string in bytes
 --      type     - type of the string. ASCSTR_... constant (see nalt.hpp)
 --      buf      - output buffer
 --      bufsize  - size of output buffer
 --      usedsize - on exit, number of bytes in buf filled with string data
 --                 (not counting terminating zeroes)
 --                 can be NULL if not needed
 --      flags    - combination of ACFOPT_...
 -- returns 1-ok, 0-ascii string is too long and was truncated
foreign import ccall "get_ascii_contents2"
  get_ascii_contents2 :: CUInt -> CUInt -> CUInt -> CString ->
                         CUInt -> Ptr CUInt -> CInt -> IO CUChar
 -- determine maximum length of ascii string
 --      ea           - starting address
 --      strtype      - string type. ASCSTR_... constant (see nalt.hpp)
 --      options      - combination of ALOPT_... bits, or 0
 -- Returns length of the string in bytes, including the terminating byte(s), if any
foreign import ccall "get_max_ascii_length"
  get_max_ascii_length :: CUInt -> CUInt -> CUInt -> IO CUInt

getString :: EA -> Int -> Int -> IO String
getString ea strType options = do
  clen <- get_max_ascii_length (cui ea)
          (cui strType) (cui options)
  let len = fromIntegral clen
  allocaBytes len $ \ptr -> do
    get_ascii_contents2 (CUInt ea) clen (cui strType) ptr clen nullPtr 0
    peekCString ptr

getCString :: EA -> IO String
getCString ea = getString ea (#const ASCSTR_C) (#const ALOPT_IGNHEADS)

getUString :: EA -> IO String
getUString ea = getString ea (#const ASCSTR_UNICODE) (#const ALOPT_IGNHEADS)

---------------------------------------------------------------------
--                            Disasm
 -- Generate text represention of the instruction mnemonics
 --      ea - linear address
 --      buf - output buffer
 --      bufsize - size of output buffer
 -- This function will generate the text represention of the instruction mnemonics,
 -- like 'mov', 'add', etc.
 -- If the instruction is not present in the database, it will be created.
 -- This function will also fill the 'cmd' structure.
 -- Returns: pointer to buf or NULL if failure
foreign import ccall "ua_mnem"
  ua_mnem :: EA -> CString -> CUInt -> IO CString
getMnem :: EA -> IO (Maybe String)
getMnem ea =
  allocaBytes 0x20 $ \buf -> do
    r <- ua_mnem ea buf 0x20
    if r == nullPtr then
      return Nothing
     else do
      mnem <- peekCString buf
      return $ Just mnem

 -- Generate text repesentation for operand #n
 --      ea - linear address
 --      buf - output buffer
 --      bufsize - size of output buffer
 --      n - operand number (0,1,2...)
 --      flags - combination of GETN_... constants
 --              Currently only GETN_NODUMMY is allowed
 -- This function will generate the text represention of the specified operand.
 -- If the instruction is not present in the database, it will be created.
 -- This function will also fill the 'cmd' structure.
 -- Returns: success
foreign import ccall "ua_outop2"
  ua_outop2 :: EA -> CString -> CUInt -> CUInt -> CUInt -> IO CUChar
getOp :: EA -> Int -> IO (Maybe String)
getOp ea n =
  allocaBytes 0x100 $ \buf -> do
    c <- ua_outop2 ea buf 0x100 (cui n) 0
    if c == 0 then
      return Nothing
    else
      allocaBytes 0x100 $ \s -> do
        let l = tag_remove buf s 0x100
        if l == -1 then
          return Nothing
        else do
          op <- peekCString s
          return $ Just op

 -- Remove color escape sequences from a string
 --      inptr   - input colored string.
 --      buf     - output buffer
 --                if == NULL, then return -1
 --      bufsize - size of output buffer
 --                if == 0, then don't check size of output buffer
 -- input and output buffer may be the same
 -- returns: length of resulting string, -1 if error
foreign import ccall "tag_remove"
  tag_remove :: CString -> CString -> CUInt -> CUInt


foreign import ccall "&cmd" cmd :: Ptr Insn
data OpType = Void | Reg | Mem | Phrase | Displ | Imm | Far |
              Near | Idpspec0 | Idpspec1 | Idpspec2 |
              Idpspec3 | Idpspec4 | Idpspec5
            deriving (Eq, Enum, Show)
cint2optype :: CUChar -> OpType
cint2optype i =
  case i of
  0 -> Void
  1 -> Reg
  2 -> Mem
  3 -> Phrase
  4 -> Displ
  5 -> Imm
  6 -> Far
  7 -> Near
  8 -> Idpspec0
  9 -> Idpspec1
  10 -> Idpspec2
  11 -> Idpspec3
  12 -> Idpspec4
  13 -> Idpspec5

data Insn = Insn { cs      :: EA
                 , ip      :: EA
                 , ea      :: EA
                 , itype   :: Word16
                 , size    :: Word16
                 , opNum   :: Int
                 , opTypes :: [OpType] }
            deriving (Show)

-- Generated by cppgen/ua
instance Storable Insn where
  sizeOf _ = (#size insn_t)
  alignment = sizeOf
  peek ptr = do
    cs <- (#peek insn_t, cs) ptr :: IO CEA
    ip <- (#peek insn_t, ip) ptr :: IO CEA
    ea <- (#peek insn_t, ea) ptr :: IO CEA
    itype <- (#peek insn_t, itype) ptr :: IO CUShort
    size <- (#peek insn_t, size) ptr :: IO CUShort
    op0type <- (#peek insn_t, Operands[0]) ptr :: IO CUChar
    op1type <- (#peek insn_t, Operands[1]) ptr :: IO CUChar
    op2type <- (#peek insn_t, Operands[2]) ptr :: IO CUChar
    op3type <- (#peek insn_t, Operands[3]) ptr :: IO CUChar
    op4type <- (#peek insn_t, Operands[4]) ptr :: IO CUChar
    op5type <- (#peek insn_t, Operands[5]) ptr :: IO CUChar

    let optypes' = map cint2optype [op0type, op1type, op2type,
                                    op3type, op4type, op5type]

    let optypes = [x | x <- optypes', x /= Void ]
    return $ Insn (fromIntegral cs) (fromIntegral ip)
      (fromIntegral ea) (fromIntegral itype) (fromIntegral size)
      (length optypes) optypes
  poke = undefined

getInsn :: EA -> IO Insn
getInsn ea =
  peek cmd

data Cmd = Cmd { mnem :: String
               , ops  :: [String]
               , insn :: Insn }
instance Show Cmd where
  show (Cmd mnem ops insn) = mnem ++ " " ++ intercalate ", " ops
  showsPrec _ (Cmd mnem ops insn) = shows (mnem ++ " " ++ intercalate ", " ops)

getCmd :: EA -> IO (Maybe Cmd)
getCmd ea = do
  mnem <- getMnem ea
  insn <- getInsn ea
  ops' <- mapM (getOp ea) [0..(opNum insn)]
  let ok = any isNothing ops'
      ops = filter (not . null ) $ catMaybes ops'
  case (mnem, ok) of
   (Nothing, _) -> return Nothing
   (_, True) -> return Nothing
   (Just m, _) -> return $ Just $ Cmd m ops insn

---------------------------------------------------------------------

---------------------------------------------------------------------
--                             Hotkeys
type Callback = CUInt -> CUInt -> IO CUInt
type CallbackWrap =  (() -> IO()) -> CUInt -> CUInt -> IO CUInt
-- foreign import ccall "wrapper"
foreign import stdcall "wrapper"
  wrap :: Callback -> IO (FunPtr Callback)

 -- Add/remove a built-in IDC function
 --      name - function name to modify
 --      fp   - pointer to the function which will handle this IDC function
 --             == NULL: remove the specified function
 --      args - prototype of the function, zero terminated array of VT_...
 --      extfun_flags - combination of EXTFUN_... constants or 0
 -- returns: success
 -- This function does not modify the predefined kernel functions
 -- Example:

 --  static const char myfunc5_args[] = { VT_LONG, VT_STR, 0 };
 --  static error_t idaapi myfunc5(idc_value_t *argv, idc_value_t *res)
 --  {
 --    msg("myfunc is called with arg0=%a and arg1=%s\n", argv[0].num, argv[1].str);
 --    res->num = 5;     // let's return 5
 --    return eOk;
 --  }

 --  after:
 --      set_idc_func("MyFunc5", myfunc5, myfunc5_args);
 --  there is a new IDC function which can be called like this:
 --      MyFunc5(0x123, "test");
foreign import ccall "set_idc_func_ex"
  set_idc_func_ex :: CString -> FunPtr Callback ->
                      Ptr CUInt -> CInt -> IO CUChar

setIdcFunc :: String -> Callback -> IO Bool
setIdcFunc name callback = do
  callback' <- wrap callback
  r <- withArray [CUInt 0] $
       \args ->
        withCString name (
          \name' -> set_idc_func_ex name' callback' args 0)
  case r of
   0 -> return False
   _ -> return True


---------------------------------------------------------------------

---------------------------------------------------------------------
--                           netnode.hpp/nalt.hpp

foreign import ccall "&RootNode" rootNode :: Ptr CUInt
 -- Get altval element of the specified array
 --      alt - index into array of altvals
 --      tag - tag of array. may be omitted
 -- returns: value of altval element. Unexistent altval members are returned
 --          as zeroes
foreign import ccall "netnode_altval"
  netnode_altval :: CUInt -> CUInt -> CUChar -> IO CUInt

getImagebase :: IO EA
getImagebase = do
  rn <- peek rootNode
  r <- netnode_altval rn (#const RIDX_ALT_IMAGEBASE) 0x41
  return $ fromIntegral r

 -- Get value of netnode
 -- Value of netnode  - a value: arbitary sized object, max size is MAXSPECSIZE
 -- returns: length of value, -1 - no value present
 -- NB: do not use this function for strings, see valstr()
foreign import ccall "netnode_valobj"
  netnode_valobj :: CUInt -> CString -> CUInt -> IO CInt

getInputFileName :: IO (Maybe String)
getInputFileName = do
  rn <- peek rootNode
  allocaBytes 0x400 $ \s -> do
    r <- netnode_valobj rn s (cui 0x400)
    if r == -1 then
      return Nothing
    else do
      name <- peekCString s
      return $ Just name
---------------------------------------------------------------------

---------------------------------------------------------------------
--                               Codes
relHere :: () -> IO ()
relHere _ = do
  path <- getInputFileName
  here <- here
  imgBase <- getImagebase
  let filename = takeBaseName $ fromJust path
  msgLn $ filename ++ "+" ++ (hex $ here - imgBase)
  return ()

run = do
  delHotKey "f12"
  addHotKey "f12" (wrapCallback relHere)
---------------------------------------------------------------------

---------------------------------------------------------------------
--                               bytes.hpp



---------------------------------------------------------------------
 -- Set an indented comment
 --      ea     - linear address
 --      comm   - comment string
 --      rptble - is repeatable?
 -- returns: 1-ok, 0-failure
foreign import ccall "set_cmt"
  set_cmt :: CEA -> CString -> CUChar -> IO CUChar

 -- Get an indented comment
 --      ea     - linear address. may point to tail byte, the function
 --               will find start of the item
 --      rptble - get repeatable comment?
 --      buf - output buffer, may be NULL
 --      bufsize - size of output buffer
 -- Returns: size of comment or -1
foreign import ccall "get_cmt"
  get_cmt :: CEA -> CUChar -> CString -> CUInt -> IO CChar

getComment :: EA -> IO (Maybe String)
getComment ea =
  allocaBytes maxStr $ \ptr -> do
    r <- get_cmt (cui ea) 0 ptr (cui maxStr)
    if r /= (-1) then
      liftM Just (peekCString ptr)
    else return Nothing

setComment :: EA -> String -> IO ()
setComment ea cmt = do
  withCString cmt $ \s ->
                     set_cmt (cui ea) s 0
  return ()


---------------------------------------------------------------------
--                               funcs.hpp

type PFuncT = Ptr FuncT
data FuncT  = FuncT { funcStart :: EA,
                      funcEnd   :: EA }
instance Storable FuncT where
  sizeOf _ = #size func_t
  alignment = sizeOf
  peek ptr = do
    s <- (#peek func_t, startEA) ptr :: IO CEA
    e <- (#peek func_t, endEA) ptr :: IO CEA
    return $ FuncT (fromIntegral s) (fromIntegral e)
  poke = undefined

instance Show FuncT where
  show f = "Function at " ++ (hex $ funcStart f)

 -- Get pointer to function structure by address
 --      ea - any address in a function
 -- Returns ptr to a function or NULL
 -- This function returns a function entry chunk
foreign import ccall "get_func"
  get_func :: CEA -> IO (PFuncT)

getFunc :: EA -> IO PFuncT
getFunc ea = get_func (cui ea)


-- Get total number of functions in the program
foreign import ccall "get_func_qty"
  get_func_qty :: IO (CUInt)

getFuncQty :: IO Int
getFuncQty = fromIntegral <$> get_func_qty

-- Get pointer to function structure by number.
-- \param n  number of function, is in range 0..get_func_qty()-1
-- \return ptr to a function or NULL.
-- This function returns a function entry chunk.
foreign import ccall "getn_func"
  getn_func :: CUInt -> IO (PFuncT)

getNFunc :: Int -> IO PFuncT
getNFunc n = getn_func (cui n)

-- Get the containing tail chunk of 'ea'.
-- \retval -1   means 'does not contain ea'
-- \retval  0   means the 'pfn' itself contains ea
-- \retval >0   the number of the containing function tail chunk
foreign import ccall "get_func_chunknum"
  get_func_chunknum :: PFuncT -> CEA -> IO (Int)

funcContains :: PFuncT -> EA -> IO Bool
funcContains pfn ea = (not . (< 0)) <$> get_func_chunknum pfn (cui ea)

-- Get ordinal number of a function.
-- \param ea  any address in the function
-- \return number of function (0..get_func_qty()-1).
-- -1 means 'no function at the specified address'.
foreign import ccall "get_func_num"
  get_func_num :: CEA -> IO (CInt)

getFuncNum :: EA -> IO (Maybe Int)
getFuncNum ea = do
  n <- get_func_num (cui ea)
  return $ if n >= 0 then Just $ fromIntegral n
            else Nothing

-- Get pointer to the previous function.
-- \param ea  any address in the program
-- \return ptr to function or NULL if previous function doesn't exist
foreign import ccall "get_prev_func"
  get_prev_func :: CEA -> IO (PFuncT)

getPrevFunc :: EA -> IO (Maybe PFuncT)
getPrevFunc ea = do
  f <- get_prev_func (cui ea)
  return $ if f /= nullPtr then Just f
            else Nothing

-- Get pointer to the next function.
-- \param ea  any address in the program
-- \return ptr to function or NULL if next function doesn't exist
foreign import ccall "get_next_func"
  get_next_func :: CEA -> IO (PFuncT)

getNextFunc :: EA -> IO (Maybe PFuncT)
getNextFunc ea = do
  f <- get_next_func (cui ea)
  return $ if f /= nullPtr then Just f
            else Nothing

data Area = Area { areaStart :: EA,
                   areaEnd   :: EA }

instance Storable Area where
  sizeOf _ = #size area_t
  alignment = sizeOf
  peek ptr = do
    s <- (#peek area_t, startEA) ptr :: IO CEA
    e <- (#peek area_t, endEA) ptr :: IO CEA
    return $ Area (fromIntegral s) (fromIntegral e)
  poke ptr a = do
    (#poke area_t, startEA) ptr (areaStart a)
    (#poke area_t, endEA) ptr (areaEnd a)
    return ()

instance Show Area where
  show a = "Area from " ++ (hex $ areaStart a) ++ " to " ++ (hex $ areaEnd a)

-- Get function limits.
-- The function limits is the minimal area containing all addresses
-- belonging to the function
-- \retval true   ok
-- \retval false  wrong arguments
foreign import ccall "get_func_limits"
  get_func_limits :: PFuncT -> Ptr (Area) -> IO (CUChar)

getFuncLimits :: PFuncT -> IO (Maybe Area)
getFuncLimits pfn = alloca $
  \parea -> do
    r <- get_func_limits pfn parea
    if r /= 0 then peek parea >>= return . Just
      else return Nothing

foreign import ccall "get_next_func_addr"
  get_next_func_addr :: PFuncT -> CEA -> IO (CEA)

getNextFuncAddr :: PFuncT -> EA -> IO EA
getNextFuncAddr pfn ea = fromIntegral <$> get_next_func_addr pfn (cui ea)

-- From helpers library because of inline public methods in funcs.hpp
foreign import ccall "get_func_items"
  get_func_items :: PFuncT -> CEA -> Ptr (Ptr CEA) -> Ptr CInt -> IO ()

-- Returns eas of all function instructions
getFuncItemsEA :: PFuncT -> EA -> IO ([EA])
getFuncItemsEA pfn ea = do
  alloca $ \ppEas ->
    alloca $ \pSize ->
      do
        get_func_items pfn (cui ea) ppEas pSize
        size <- fromIntegral <$> peek pSize
        pEas <- peek ppEas

        if pEas /= nullPtr then do
          ret <- peekArray size pEas
          free pEas
          return $ map fromIntegral ret
        else return []

getFuncItems :: EA -> IO ([EA])
getFuncItems ea = do
  f <- getFunc ea
  getFuncItemsEA f ea

getFuncAsm :: EA -> IO [Cmd]
getFuncAsm ea = catMaybes <$> (getFuncItems ea >>= mapM getCmd)

-- funcTailIteratorSetEA :: FuncTailIterT -> EA -> IO Bool
-- funcTailIteratorSetEA fti ea = do


-- data Function = Function { baseEA :: EA }
--               deriving (Show)
--
-- func :: EA -> IO Function
-- func ea = Function ea



---------------------------------------------------------------------
--                               funcs.hpp

data FCFlags = FCPrint | FCNoext | FCPreds | FCAppnd | FCChkBreak

data FlowChart = FlowChart { fcBounds  :: Area,
                             fcFlags   :: [FCFlags],
                             fcPfn     :: PFuncT}

type PFlowChart = Ptr FlowChart

instance Show FlowChart where
  show fc = "FlowChart with " ++ (show $ fcBounds fc)

instance Storable FlowChart where
  sizeOf _ = #size qflow_chart_t
  alignment = sizeOf
  peek ptr = do
    a <- (#peek qflow_chart_t, bounds) ptr :: IO Area
    pfn <- (#peek qflow_chart_t, pfn)  ptr :: IO PFuncT
    f <- (#peek qflow_chart_t, flags)  ptr :: IO CInt
    return $ FlowChart a [] pfn
  poke ptr fc = do
    (#poke qflow_chart_t, bounds) ptr (fcBounds fc)
    (#poke qflow_chart_t, pfn) ptr (fcPfn fc)
    (#poke qflow_chart_t, flags) ptr (ci 4)
    return ()

type PBasicBlock = Ptr BasicBlock
data BasicBlock = BasicBlock { bbStartEA :: EA,
                               bbEndEA   :: EA,
                               bbPred    :: [EA],
                               bbSucc    :: [EA] }

peekListOfInts :: Ptr () -> IO [EA]
peekListOfInts ptr =
  alloca $ \ppEas ->
    alloca $ \pSize ->
      do
        get_intseq_items ptr ppEas pSize
        size <- fromIntegral <$> peek pSize
        pEas <- peek ppEas

        if pEas /= nullPtr then do
          ret <- peekArray size pEas
          free pEas
          return $ map fromIntegral ret
        else return []

instance Storable BasicBlock where
  sizeOf _ = #size qbasic_block_t
  alignment = sizeOf
  peek ptr = do
    s <- (#peek qbasic_block_t, startEA) ptr :: IO CEA
    e <- (#peek qbasic_block_t, endEA) ptr   :: IO CEA
    succ' <- peekListOfInts ((#ptr qbasic_block_t, succ) ptr)
    pred' <- peekListOfInts ((#ptr qbasic_block_t, pred) ptr)
    return $ BasicBlock (fromIntegral s) (fromIntegral e) pred' succ'
  poke = undefined

instance Show BasicBlock where
  show bb = "Basic Block [" ++ (hex $ bbStartEA bb) ++
            ":" ++ (hex $ bbEndEA bb) ++ "] pred: [" ++
            (intercalate ", " $ map hex $ bbPred bb) ++ "] succ: [" ++
            (intercalate ", " $ map hex $ bbSucc bb) ++ "]"

foreign import ccall "qflow_chart_create"
  qflow_chart_create :: CString -> PFuncT -> CEA -> CEA -> CInt ->
                        IO (PFlowChart)

foreign import ccall "qflow_chart_release"
  qflow_chart_release :: PFlowChart -> IO ()

foreign import ccall "qflow_chart_size"
  qflow_chart_size :: PFlowChart -> IO (CInt)

foreign import ccall "qflow_chart_get_block"
  qflow_chart_get_block :: PFlowChart -> CInt -> IO (PBasicBlock)

foreign import ccall "get_intseq_items"
  get_intseq_items :: Ptr () -> Ptr (Ptr CInt) -> Ptr (CInt) -> IO ()

flowChartCreate :: PFuncT -> Int -> IO (PFlowChart)
flowChartCreate pfn flags =
  withCString "" $ \cs ->
    qflow_chart_create cs pfn (cui 0) (cui 0) (ci flags)

flowChartRelease :: PFlowChart -> IO ()
flowChartRelease pfc = qflow_chart_release pfc

flowChartGetBlock :: PFlowChart -> IO [BasicBlock]
flowChartGetBlock pfc = do
  n <- fromIntegral <$> qflow_chart_size pfc
  mapM (\x -> qflow_chart_get_block pfc x >>= peek) $ map ci [0..n-1]

flowChartForFunc :: EA -> IO [BasicBlock]
flowChartForFunc ea = do
  f <- getFunc ea
  fc <- flowChartCreate f (#const FC_PREDS)
  bbs <- flowChartGetBlock fc
  flowChartRelease fc
  return bbs

---------------------------------------------------------------------
