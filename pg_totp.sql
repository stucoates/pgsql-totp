--
-- Implementation of the OATH TOTP algorithm in pl/pgsql
--
--  Ported from the reference implementation at:
--   https://tools.ietf.org/html/rfc6238
--
--  Author: Stu Coates - stu@stucoates.com
--
-- Note: requires pgcrypto PostgreSQL extension
--
-------------------------------------------------------------------------------
--
-- Copyright (c) 2016, Stu Coates
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without 
-- modification, are permitted provided that the following conditions
-- are met:
--
-- 1. Redistributions of source code must retain the above copyright notice,
--    this list of conditions and the following disclaimer.
-- 
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the 
--    documentation and/or other materials provided with the distribution.
-- 
-- 3. Neither the name of the copyright holder nor the names of its 
--    contributors may be used to endorse or promote products derived 
--    from this software without specific prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
-- ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
-- LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
-- CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
-- SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
-- INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
-- CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
-- ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.
--
-------------------------------------------------------------------------------

begin;

create extension if not exists pgcrypto;

--
-- Create a bytea from a hex value in a string
--
create or replace function _totp_hex_to_bytea(h varchar) returns bytea as
$$
declare
  v_cmd text;
  v_ba bytea;
begin
  if length(h) = 0 then
    return ''::bytea;
  end if;
  if length(h) % 2 = 1 then
    h:='0' || h;
  end if;
  v_cmd:='select E''\\x' || h || '''::bytea'; 
  execute v_cmd into v_ba;
  return v_ba;
end;
$$
language 'plpgsql' strict immutable;

--
-- Create a zero'd bytea of a given length
--
create or replace function _totp_dim_bytea(p_size int) returns bytea as
$$
declare
  v_zeros text:='';
  v_i int:=0;
begin
  for v_i in 0 .. p_size-1 loop
    v_zeros:=v_zeros || '00';
  end loop;
  return _totp_hex_to_bytea(v_zeros);
end;
$$
language 'plpgsql' strict immutable;

--
-- Generate the OATH TOTP code
--
create or replace function generateTOTP(
  p_key text,            -- the secret as a hex string
  p_time text,           -- the number of time units since epoch
  p_return_digits int,   -- the number of digits that is required
  p_crypto text          -- the hash algorithm, pick from sha1, sha256
  ) returns text as
$$
declare
  v_digits_power int[] := '{1,10,100,1000,10000,100000,1000000,10000000,100000000}';
  v_result text;
  v_msg bytea;
  v_barray bytea;
  v_i int;
  v_hash bytea;
  v_b bytea;
  v_offset int;
  v_binary int;
  v_otp int;
begin
  v_msg:=_totp_dim_bytea(8);

  if length(p_time) > 0 then
    v_barray:=_totp_hex_to_bytea(p_time);
    if length(v_barray)=9 then
      v_i:=0;
      while v_i < 8 and v_i < length(v_barray) loop
        v_msg:=set_byte(v_msg,v_i + 8 - length(v_barray),get_byte(v_barray,v_i + 1));
        v_i:=v_i+1;
      end loop;
    else
      v_i:=0;
      while v_i < 8 and v_i < length(v_barray) loop
        v_msg:=set_byte(v_msg,v_i + 8 - length(v_barray),get_byte(v_barray,v_i));
        v_i:=v_i+1;
      end loop;
    end if;
  end if;

  v_barray:=_totp_hex_to_bytea(p_key);
  if(get_byte(v_barray,0)=0) then
    v_b:=_totp_dim_bytea(length(v_barray)-1);
    for v_i in 0 .. length(v_b)-1 loop
      v_b:=set_byte(v_b,v_i,get_byte(v_barray,v_i+1));
    end loop;
    v_hash:=hmac(v_msg,v_b,p_crypto);
  else
    v_hash:=hmac(v_msg,v_barray,p_crypto);
  end if;

  v_offset:=get_byte(v_hash,length(v_hash)-1) & 15;

  v_binary:=((get_byte(v_hash,v_offset) & 127) << 24) | ((get_byte(v_hash,v_offset+1) & 255) << 16) |
            ((get_byte(v_hash,v_offset+2) & 255) << 8) | ((get_byte(v_hash,v_offset+3) & 255));

  v_otp:=v_binary % v_digits_power[p_return_digits+1];

  v_result:=v_otp::text;
  while(length(v_result) < p_return_digits) loop
    v_result:='0' || v_result;
  end loop;

  return v_result;
end;
$$
language 'plpgsql' stable;

--
-- Wrappers for main function with reasonable defaults
--
create or replace function generateTOTP(
  p_hex_key text,
  p_time timestamp default clock_timestamp() at time zone 'utc',
  p_code_digits int default 6,           -- number of digits in the code
  p_hash_algorithm text default 'sha1',
  p_rotate_seconds int default 60        -- how often the code changes
  ) returns text as
$$
begin
  return generateTOTP(p_hex_key,to_hex(extract(epoch from p_time)::bigint / p_rotate_seconds),p_code_digits,p_hash_algorithm);
end;
$$ language 'plpgsql' stable;

create or replace function generateTOTP256(
  p_hex_key text,
  p_time timestamp default clock_timestamp() at time zone 'utc',
  p_code_digits int default 6
  ) returns text as
$$
begin
  return generateTOTP(p_hex_key,p_time,p_code_digits,'sha256');
end;
$$ language 'plpgsql' stable;

create or replace function generateTOTP512(
  p_hex_key text,
  p_time timestamp default clock_timestamp() at time zone 'utc',
  p_code_digits int default 6
  ) returns text as
$$
begin
  return generateTOTP(p_hex_key,p_time,p_code_digits,'sha512');
end;
$$ language 'plpgsql' stable;

--
-- Helper function to check an entered code against generated
--
--  Note: allows for clock drift from the client system
--
create or replace function checkTOTP(p_hex_key text,p_guess text,p_drift interval default '30 seconds'::interval,p_time timestamp default clock_timestamp() at time zone 'utc') returns boolean as
$$
begin
  return exists (select * from unnest(array[
  	generateTOTP(p_hex_key,p_time-p_drift),
  	generateTOTP(p_hex_key,p_time),
  	generateTOTP(p_hex_key,p_time+p_drift)
  	]) t where t=p_guess);
end;
$$ language 'plpgsql' stable;

--
-- Easy function to create a new TOTP secret key
--
create or replace function makeKey(p_bytes integer default 64) returns text as
$$
begin
  return encode(gen_random_bytes(p_bytes),'hex');
end;
$$ language 'plpgsql' stable;

commit;
