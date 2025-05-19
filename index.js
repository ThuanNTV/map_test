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
import helmet from "helmet";
import compression from "compression";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import { createHash } from "crypto";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const app = express();
const detector = new DeviceDetector();
const LOG_FILE = path.join(__dirname, "logs.csv");

// Cấu hình bảo mật cơ bản
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "'unsafe-eval'",
          "unpkg.com",
          "cdn.jsdelivr.net",
          "cdnjs.cloudflare.com",
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "unpkg.com",
          "cdn.jsdelivr.net",
          "cdnjs.cloudflare.com",
        ],
        imgSrc: [
          "'self'",
          "data:",
          "blob:",
          "*.tile.openstreetmap.org",
          "a.tile.openstreetmap.org",
          "b.tile.openstreetmap.org",
          "c.tile.openstreetmap.org",
        ],
        connectSrc: [
          "'self'",
          "ip-api.com",
          "*.tile.openstreetmap.org",
          "a.tile.openstreetmap.org",
          "b.tile.openstreetmap.org",
          "c.tile.openstreetmap.org",
        ],
        fontSrc: ["'self'", "cdnjs.cloudflare.com", "data:"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "cross-origin" },
    dnsPrefetchControl: true,
    frameguard: { action: "deny" },
    hidePoweredBy: true,
    hsts: true,
    ieNoOpen: true,
    noSniff: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    xssFilter: true,
  })
);

// Nén response
app.use(compression());

// Giới hạn request rate
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 phút
  max: 100, // giới hạn mỗi IP 100 request trong 15 phút
  message: {
    status: "error",
    message: "Quá nhiều request, vui lòng thử lại sau",
  },
});
app.use("/log", limiter);

// Cookie parser
app.use(cookieParser());

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
    "Time,IP,OS,Device,Client,Engine,Browser Type,Platform,Device Model,Browser Version,Referrer,City,Region,Country,Zip,Lat,Lon,Timezone,ISP,Org,ASN,Languages,URL,Location,Consent Given\n"
  );
}

// Hàm xác thực timestamp
function validateTimestamp(timestamp) {
  const now = new Date();
  const logTime = new Date(timestamp);
  const diff = Math.abs(now - logTime);
  return diff <= 24 * 60 * 60 * 1000; // Cho phép sai số 24 giờ
}

// Hàm xác thực geolocation
async function validateGeolocation(ip, lat, lon) {
  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}`);
    const data = response.data;
    if (data.status === "success") {
      const ipLat = parseFloat(data.lat);
      const ipLon = parseFloat(data.lon);
      const userLat = parseFloat(lat);
      const userLon = parseFloat(lon);

      // Tính khoảng cách giữa 2 điểm (Haversine formula)
      const R = 6371; // Bán kính trái đất (km)
      const dLat = ((userLat - ipLat) * Math.PI) / 180;
      const dLon = ((userLon - ipLon) * Math.PI) / 180;
      const a =
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos((ipLat * Math.PI) / 180) *
          Math.cos((userLat * Math.PI) / 180) *
          Math.sin(dLon / 2) *
          Math.sin(dLon / 2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
      const distance = R * c;

      return distance <= 50; // Cho phép sai số 50km
    }
    return false;
  } catch (error) {
    console.error("Error validating geolocation:", error);
    return false;
  }
}

app.get("/log", async (req, res) => {
  try {
    // Chỉ log cảnh báo hoặc lỗi khi production
    // console.log('[DEBUG][BACKEND] Nhận request /log');
    // BỎ kiểm tra cookie consent để test
    // const consentGiven = req.cookies.consent === "true";
    // if (!consentGiven) {
    //   return res.status(403).json({
    //     status: "error",
    //     message: "Cookie consent required",
    //   });
    // }

    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const userAgent = req.headers["user-agent"];
    const referer = req.headers.referer || "Direct";
    // console.log("[DEBUG][BACKEND] IP:", ip);
    // console.log("[DEBUG][BACKEND] UserAgent:", userAgent);
    // console.log("[DEBUG][BACKEND] Referer:", referer);

    // Sử dụng device-detector-js để phân tích user agent
    const device = detector.parse(userAgent);
    const deviceType = device.device?.type || "Unknown";
    const os = device.os?.name || "Unknown";
    const browser = device.client?.name || "Unknown";
    const browserVersion = device.client?.version || "Unknown";
    // console.log(
    //   "[DEBUG][BACKEND] Device:",
    //   deviceType,
    //   os,
    //   browser,
    //   browserVersion
    // );

    const timestamp = new Date().toISOString();
    // console.log("[DEBUG][BACKEND] Timestamp:", timestamp);

    // Xác thực timestamp
    if (!validateTimestamp(timestamp)) {
      console.warn(`[BACKEND] Invalid timestamp detected for IP ${ip}`);
    }

    // Lấy thông tin vị trí từ IP
    const geoResponse = await fetch(`http://ip-api.com/json/${ip}`);
    const geoData = await geoResponse.json();
    const location =
      geoData.status === "success"
        ? `${geoData.city}, ${geoData.regionName}, ${geoData.country}`
        : "Unknown";
    // console.log("[DEBUG][BACKEND] GeoData:", geoData);

    // Lấy thông tin chi tiết từ request
    const {
      screenWidth,
      screenHeight,
      colorDepth,
      pixelRatio,
      timezone,
      language,
      doNotTrack,
      cookiesEnabled,
      localStorage,
      sessionStorage,
      touchSupport,
      batteryLevel,
      connectionType,
      deviceMemory,
      hardwareConcurrency,
      plugins,
      fonts,
      apiSupport,
      securityInfo,
      peripheralInfo,
      performanceInfo,
      networkInfo,
      latitude,
      longitude,
    } = req.query;
    // console.log("[DEBUG][BACKEND] Query:", req.query);

    // Xác thực geolocation nếu có
    if (latitude && longitude) {
      const isValidLocation = await validateGeolocation(
        ip,
        latitude,
        longitude
      );
      if (!isValidLocation) {
        console.warn(`[BACKEND] Suspicious geolocation detected for IP ${ip}`);
      }
    }

    // Tạo log entry với tất cả thông tin
    const logEntry = [
      timestamp,
      ip,
      userAgent,
      referer,
      deviceType,
      os,
      browser,
      browserVersion,
      location,
      geoData.lat || "Unknown",
      geoData.lon || "Unknown",
      geoData.timezone || "Unknown",
      geoData.isp || "Unknown",
      geoData.org || "Unknown",
      geoData.as || "Unknown",
      screenWidth || "Unknown",
      screenHeight || "Unknown",
      colorDepth || "Unknown",
      pixelRatio || "Unknown",
      timezone || "Unknown",
      language || "Unknown",
      doNotTrack || "Unknown",
      cookiesEnabled || "Unknown",
      localStorage || "Unknown",
      sessionStorage || "Unknown",
      touchSupport || "Unknown",
      batteryLevel || "Unknown",
      connectionType || "Unknown",
      deviceMemory || "Unknown",
      hardwareConcurrency || "Unknown",
      plugins || "Unknown",
      fonts || "Unknown",
      apiSupport || "Unknown",
      securityInfo || "Unknown",
      peripheralInfo || "Unknown",
      performanceInfo || "Unknown",
      networkInfo || "Unknown",
      // consentGiven, // đã bỏ
    ].join(",");
    // console.log("[DEBUG][BACKEND] Log entry:", logEntry);

    // Ghi log vào file
    fs.appendFileSync(LOG_FILE, logEntry + "\n");
    // console.log("[DEBUG][BACKEND] Đã ghi log vào file");

    res.json({ status: "ok" });
  } catch (error) {
    console.error("[BACKEND] Error logging:", error);
    res.status(500).json({ status: "error", message: error.message });
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

// Thêm chức năng yêu cầu vị trí chính xác của người dùng
app.get("/get-location", (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Get Location</title>
      </head>
      <body>
        <h2>Your Location</h2>
        <p id="demo"></p>
        <script>
          const x = document.getElementById("demo");

          function getLocation() {
            if (navigator.geolocation) {
              navigator.geolocation.getCurrentPosition(success, error);
            } else {
              x.innerHTML = "Geolocation is not supported by this browser.";
            }
          }

          function success(position) {
            x.innerHTML = "Latitude: " + position.coords.latitude +
            "<br>Longitude: " + position.coords.longitude;
          }

          function error() {
            alert("Sorry, no position available.");
          }

          getLocation();
        </script>
      </body>
    </html>
  `);
});

// Thêm route cho cookie consent
app.get("/consent", (req, res) => {
  res.cookie("consent", "true", {
    maxAge: 365 * 24 * 60 * 60 * 1000, // 1 năm
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
  res.json({ status: "ok" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 App running at http://localhost:${PORT}`);
});
