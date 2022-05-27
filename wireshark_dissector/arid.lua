local tii_arid = Proto("TII-ARID", "TII ARID Protocol")

-- Header fields
group_id        = ProtoField.bytes("tii_arid.group_id", "Drone Group ID")
latitude        = ProtoField.bytes("tii_arid.latitude", "Latitude [deg]")
longitude       = ProtoField.bytes("tii_arid.longitude", "Longitude [deg]")
altitude        = ProtoField.bytes("tii_arid.altitude", "Altitude [m]")
speed           = ProtoField.bytes("tii_arid.speed", "Speed [m/s]")
cog             = ProtoField.bytes("tii_arid.cog", "Course Over Ground [deg]")
latitude_uas    = ProtoField.bytes("tii_arid.latitude_uas", "Latitude UAS [deg]")
longitude_uas   = ProtoField.bytes("tii_arid.longitude_uas", "Longitude UAS [deg]")
altitude_uas    = ProtoField.bytes("tii_arid.altitude_uas", "Altitude UAS [m]")
timestamp       = ProtoField.uint32("tii_arid.timestamp", "Timestamp [s]", base.DEC)
es              = ProtoField.bytes("tii_arid.es", "Emergency Code")
len             = ProtoField.uint16("tii_arid.len", "Signature Length [B]", base.DEC)
sign            = ProtoField.bytes("tii_arid.sign", "Signature")

-- Register protocol fields
tii_arid.fields = {group_id, latitude, longitude, altitude, speed, cog, latitude_uas, longitude_uas,
                   altitude_uas, timestamp, es, len, sign}

-- TII_ARID_ETYPE Ethertype represents a tii_arid packet
local TII_ARID_ETYPE = 0xa21d

local etypetable = DissectorTable.get("ethertype")
local etype_orig = etypetable:get_dissector(TII_ARID_ETYPE)
local data_dis = Dissector.get("data")

function tii_arid.dissector(tvbuf, pinfo, tree)

    if etype_orig ~= nil then
        etype_orig:call(tvbuf, pinfo, tree)
    else
        data_dis:call(tvbuf, pinfo, tree)
    end

    pinfo.cols.protocol:set("TII ARID")

    local subtree = tree:add(tii_arid, tvbuf(0, tvbuf:len()), "TII ARID Protocol Data")

    -- Header
    subtree:add(group_id, tvbuf(0, 4))
    subtree:add(latitude, tvbuf(4, 4))
    subtree:add(longitude, tvbuf(8, 4))
    subtree:add(altitude, tvbuf(12, 4))
    subtree:add(speed, tvbuf(16, 4))
    subtree:add(cog, tvbuf(20, 4))
    subtree:add(latitude_uas, tvbuf(24, 4))
    subtree:add(longitude_uas, tvbuf(28, 4))
    subtree:add(altitude_uas, tvbuf(32, 4))
    subtree:add(timestamp, tvbuf(36, 4))
    subtree:add(es, tvbuf(40, 1))
    subtree:add(len, tvbuf(41, 2))
    subtree:add(sign, tvbuf(43, tvbuf:len() - 43))
end

etypetable:add(TII_ARID_ETYPE, tii_arid)
