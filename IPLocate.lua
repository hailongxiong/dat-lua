require "struct"

function readfile(filename)
    local inp = assert(io.open(filename, "rb"))
    local data = inp:read("*all")
    offset_addr=struct.unpack('L',string.sub(data,1,8))
    offset_owner=struct.unpack('L',string.sub(data,9,17))
    offset_info=string.sub(data,18)
    return offset_addr,offset_owner,offset_info
end

function float_to_int(x)
    if x <= 0 then
       return math.ceil(x);
    end    
    if math.ceil(x) == x then
       x = math.ceil(x);
    else
       x = math.ceil(x) - 1;
    end
    return x;
end

function mysplit(inputstr, sep)
    if sep == nil then
            sep = "%s"
    end
    local t={} ; i=1
    for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
            t[i] = str
            i = i + 1
    end
    return t
end

function locate(ip)
    local nip = 0
    if(string.find(ip,"(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)"))
    then
        ip:gsub("%d+", function(s) nip = nip * 256 + tonumber(s) end)
    else
        return "Error IP"
    end
    local record_min=0
    local base_len=64
    local record_max=float_to_int(offset_addr/base_len) - 1
    local record_mid = float_to_int((record_min + record_max)/2)
    local mult_re_ba=float_to_int(record_mid *base_len)+1
    while(record_max - record_min >= 0)
        do
            local mult_re_ba=float_to_int(record_mid *base_len)
            minip = struct.unpack('I',string.sub(offset_info,mult_re_ba,mult_re_ba+4))
            maxip = struct.unpack('I',string.sub(offset_info,mult_re_ba+4,mult_re_ba+8))
            if(nip < minip)
                then
                    record_max = record_mid - 1
            elseif((nip == minip) or (nip > minip and nip < maxip) or (nip == maxip))
                then
                        addr_begin= struct.unpack('L',string.sub(offset_info,mult_re_ba + 8 , mult_re_ba+ 16))
                        addr_length= struct.unpack('L',string.sub(offset_info,mult_re_ba + 16 ,mult_re_ba+ 24))
                        owner_begin= struct.unpack('L',string.sub(offset_info,mult_re_ba + 24 ,mult_re_ba+ 32))
                        owner_length= struct.unpack('L',string.sub(offset_info,mult_re_ba + 32 ,mult_re_ba+ 40))
                        --[[ bd_lon =struct.unpack('12n',string.sub(offset_info,mult_re_ba + 40,mult_re_ba + 52))
                        bd_lat =struct.unpack('12n',string.sub(offset_info,mult_re_ba + 52,mult_re_ba + 64))--]] 
                        wgs_lon =struct.unpack('12n',string.sub(offset_info,mult_re_ba + 40,mult_re_ba + 52))
                        wgs_lat =struct.unpack('12n',string.sub(offset_info,mult_re_ba + 52,mult_re_ba + 64))
                       --[[ radius =struct.unpack('12n',string.sub(offset_info,mult_re_ba + 88,mult_re_ba + 100))
                        scene =struct.unpack('12n',string.sub(offset_info,mult_re_ba + 100,mult_re_ba + 112))
                        accuracy =struct.unpack('12n',string.sub(offset_info,mult_re_ba + 112,mult_re_ba + 124))--]]
                        addr_bundle = string.sub(offset_info,addr_begin,addr_begin + addr_length)
                        addr=mysplit(addr_bundle,"|")
                        owner =  string.sub(offset_info,owner_begin,owner_begin + owner_length)
                        tmp_list={tostring(minip),tostring(maxip),addr[0],addr[1], addr[2], addr[3], addr[4], addr[5], addr[6],tostring(wgs_lon), tostring(wgs_lat),tostring(owner)}
                        res_list = ""
                        for key, value in pairs(tmp_list) do
                            if(value=="nil")
                                then
                                    value=""
                                end
                            res_list=res_list..value.."|"
                            end 
                        return res_list
            elseif (nip > maxip)
                then
                    record_min = record_mid + 1
            else
                return "Error Case"
            end
            record_mid = float_to_int((record_min + record_max)/2)
        end
    return 'Not Found.'
end



filename="./test.dat"
offset_addr,offset_owner,offset_info=readfile(filename)
while(true)
do
    print("Please input IP address:")
    ip = io.read()  --输入字符串  
    print(locate(ip))
end
