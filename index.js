// enhanced_ip_logger/server.js
import express from "express";
import path from "path";
import fs from "fs";
import axios from "axios";
import DeviceDetector from "device-detector-js";
import { fileURLToPath } from "url";
import { dirname } from "path";
import csvParser from "csv-parser";
import dotenv from "dotenv";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const app = express();
const detector = new DeviceDetector();
const LOG_FILE = path.join(__dirname, "logs.csv");

// Add basic auth middleware
const basicAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    res.setHeader("WWW-Authenticate", "Basic");
    return res.status(401).json({
      status: "error",
      message: "Authentication required",
    });
  }

  const auth = Buffer.from(authHeader.split(" ")[1], "base64")
    .toString()
    .split(":");
  const username = auth[0];
  const password = auth[1];

  if (
    username === process.env.ADMIN_USERNAME &&
    password === process.env.ADMIN_PASSWORD
  ) {
    next();
  } else {
    res.setHeader("WWW-Authenticate", "Basic");
    return res.status(401).json({
      status: "error",
      message: "Invalid credentials",
    });
  }
};

app.use(express.static("public"));

if (!fs.existsSync(LOG_FILE)) {
  fs.writeFileSync(
    LOG_FILE,
    "Time,IP,OS,Device,Client,Engine,Browser Type,Platform,Device Model,Browser Version,Referrer,City,Region,Country,Zip,Lat,Lon,Timezone,ISP,Org,ASN,Languages,URL,Location\n"
  );
}

app.get("/log", async (req, res) => {
  const ipRaw =
    req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
  const ip = ipRaw.split(",")[0].trim();
  const userAgent = req.headers["user-agent"];
  const time = new Date().toISOString();
  const referrer = req.headers.referer || "";
  const acceptLang = req.headers["accept-language"] || "";
  const fullUrl = `${req.protocol}://${req.get("host")}${req.originalUrl}`;

  const device = detector.parse(userAgent);
  const os = device.os?.name || "Unknown";
  const deviceType = device.device?.type || "Unknown";
  const client = device.client?.name || "Unknown";
  const engine = device.client?.engine || "";
  const browserType = device.client?.type || "";
  const platform = device.device?.brand || "";
  const deviceModel = device.device?.model || "Unknown";
  const browserVersion = device.client?.version || "Unknown";

  let city = "",
    region = "",
    country = "",
    zip = "",
    lat = "",
    lon = "",
    timezone = "",
    isp = "",
    org = "",
    as = "";
  try {
    const geo = await axios.get(
      `http://ip-api.com/json/${ip}?fields=status,message,city,regionName,country,zip,lat,lon,timezone,isp,org,as`
    );
    if (geo.data.status === "success") {
      ({
        city,
        regionName: region,
        country,
        zip,
        lat,
        lon,
        timezone,
        isp,
        org,
        as,
      } = geo.data);
    }
  } catch (err) {
    console.error(`❌ IP-API error for ${ip}:`, err.message);
  }

  // Lấy địa chỉ chính xác của khách hàng thông qua trình duyệt
  const userLocation = req.query.location || "Unknown";
  const log = `"${time}","${ip}","${os}","${deviceType}","${client}","${engine}","${browserType}","${platform}","${deviceModel}","${browserVersion}","${referrer}","${city}","${region}","${country}","${zip}","${lat}","${lon}","${timezone}","${isp}","${org}","${as}","${acceptLang}","${fullUrl}","${userLocation}"\n`;

  try {
    fs.appendFileSync(LOG_FILE, log);
    console.log(
      `✅ Logged: ${ip} - ${client} - ${city}, ${country} - Location: ${userLocation}`
    );
    res.json({ status: "ok" });
  } catch (err) {
    console.error(`❌ Error writing to log file:`, err.message);
    res.status(500).json({ status: "error", message: "Failed to log request" });
  }
});

app.get("/map", (req, res) => {
  res.sendFile(path.join(__dirname, "public/map.html"));
});

app.get("/view-logs", basicAuth, (req, res) => {
  if (!fs.existsSync(LOG_FILE)) {
    return res.status(404).json({ status: "error", message: "No logs found" });
  }

  const logs = [];
  fs.createReadStream(LOG_FILE)
    .pipe(
      csvParser({
        headers: [
          "Time",
          "IP",
          "OS",
          "Device",
          "Client",
          "Engine",
          "Browser Type",
          "Platform",
          "Device Model",
          "Browser Version",
          "Referrer",
          "City",
          "Region",
          "Country",
          "Zip",
          "Lat",
          "Lon",
          "Timezone",
          "ISP",
          "Org",
          "ASN",
          "Languages",
          "URL",
          "Location",
        ],
        skipLines: 1,
      })
    )
    .on("data", (data) => logs.push(data))
    .on("end", () => {
      const analytics = {
        totalRequests: logs.length,
        uniqueIPs: [...new Set(logs.map((l) => l.IP))].length,
        browsers: countBy(logs, "Client"),
        os: countBy(logs, "OS"),
        countries: countBy(logs, "Country"),
        cities: countBy(logs, "City"),
        times: logs.map((l) => l.Time),
        suspicious: logs.filter(
          (l) => l.Client === "Unknown" || l.BrowserType === "bot"
        ),
      };
      res.json({ status: "ok", logs, analytics });
    })
    .on("error", (err) => {
      console.error("❌ Error reading logs:", err.message);
      res.status(500).json({ status: "error", message: "Failed to read logs" });
    });
});

function countBy(array, field) {
  return array.reduce((acc, item) => {
    acc[item[field]] = (acc[item[field]] || 0) + 1;
    return acc;
  }, {});
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 App running at http://localhost:${PORT}`);
});
