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

// Thêm middleware để parse JSON request body
app.use(express.json());

const detector = new DeviceDetector();
const LOG_FILE = path.join(__dirname, "logs.csv");

// Định nghĩa các trường log và thứ tự
const LOG_FIELDS = [
  "Time",
  "IP",
  "UserAgent",
  "Referer",
  "DeviceType",
  "OS",
  "Browser",
  "BrowserVersion",
  "Location (GeoIP)",
  "Lat (GeoIP)",
  "Lon (GeoIP)",
  "Timezone (GeoIP)",
  "ISP",
  "Org",
  "ASN",
  "ScreenWidth",
  "ScreenHeight",
  "ColorDepth",
  "PixelRatio",
  "Timezone (Client)",
  "Language",
  "DoNotTrack",
  "CookiesEnabled",
  "LocalStorage",
  "SessionStorage",
  "TouchSupport",
  "BatteryLevel",
  "ConnectionType",
  "DeviceMemory",
  "HardwareConcurrency",
  "Plugins", // Có thể chứa JSON
  "Fonts", // Có thể chứa JSON
  "ApiSupport", // Có thể chứa JSON
  "SecurityInfo", // Có thể chứa JSON
  "PeripheralInfo", // Có thể chứa JSON
  "PerformanceInfo", // Có thể chứa JSON
  "NetworkInfo", // Có thể chứa JSON
];

// Hàm escape giá trị cho CSV
function escapeCsvValue(value) {
  if (value === null || value === undefined) {
    return "";
  }
  // Chuyển đổi tất cả giá trị thành chuỗi
  const stringValue = String(value);
  // Nếu giá trị chứa dấu phẩy, dấu ngoặc kép hoặc xuống dòng, bọc trong dấu ngoặc kép
  if (
    stringValue.includes(",") ||
    stringValue.includes('"') ||
    stringValue.includes("\n")
  ) {
    // Escape dấu ngoặc kép bằng cách nhân đôi nó
    const escapedValue = stringValue.replace(/"/g, '""');
    return `"${escapedValue}"`;
  }
  return stringValue;
}

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
          "https://unpkg.com",
          "https://cdn.jsdelivr.net",
          "https://cdnjs.cloudflare.com",
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://unpkg.com",
          "https://cdn.jsdelivr.net",
          "https://cdnjs.cloudflare.com",
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
  // Sử dụng header từ LOG_FIELDS
  fs.writeFileSync(LOG_FILE, LOG_FIELDS.join(",") + "\n");
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

// Thay đổi từ app.get sang app.post để nhận JSON body
app.post("/log", async (req, res) => {
  try {
    // Lấy dữ liệu từ body thay vì query
    const logData = req.body;
    console.log("[DEBUG][BACKEND] Nhận request POST /log với body:", logData);

    // BỎ kiểm tra cookie consent để test (từ phiên trước)
    // const consentGiven = req.cookies.consent === "true";
    // if (!consentGiven) {
    //   return res.status(403).json({
    //     status: "error",
    //     message: "Cookie consent required",
    //   });
    // }

    // Lấy IP, UserAgent, Referer từ headers
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const userAgent = req.headers["user-agent"];
    const referer = req.headers.referer || "Direct";
    console.log("[DEBUG][BACKEND] IP:", ip);
    console.log("[DEBUG][BACKEND] UserAgent:", userAgent);
    console.log("[DEBUG][BACKEND] Referer:", referer);

    // Sử dụng device-detector-js để phân tích user agent
    const device = detector.parse(userAgent);
    const deviceType = device.device?.type || "Unknown";
    const os = device.os?.name || "Unknown";
    const browser = device.client?.name || "Unknown";
    const browserVersion = device.client?.version || "Unknown";
    console.log(
      "[DEBUG][BACKEND] Device:",
      deviceType,
      os,
      browser,
      browserVersion
    );

    // Lấy timestamp từ data gửi lên hoặc tạo mới
    const timestamp = logData.timestamp || new Date().toISOString();
    console.log("[DEBUG][BACKEND] Timestamp:", timestamp);

    // Xác thực timestamp
    if (!validateTimestamp(timestamp)) {
      console.warn(`[BACKEND] Invalid timestamp detected for IP ${ip}`);
    }

    // Lấy thông tin vị trí từ IP (dự phòng nếu client không gửi hoặc gửi lỗi)
    let geoData = {};
    let locationGeoIP = "Unknown";
    let latGeoIP = "Unknown";
    let lonGeoIP = "Unknown";
    let timezoneGeoIP = "Unknown";
    let isp = "Unknown";
    let org = "Unknown";
    let asn = "Unknown";

    try {
      const geoResponse = await fetch(`http://ip-api.com/json/${ip}`);
      geoData = await geoResponse.json();
      if (geoData.status === "success") {
        locationGeoIP = `${geoData.city}, ${geoData.regionName}, ${geoData.country}`;
        latGeoIP = geoData.lat;
        lonGeoIP = geoData.lon;
        timezoneGeoIP = geoData.timezone;
        isp = geoData.isp;
        org = geoData.org;
        asn = geoData.as;
      }
    } catch (geoError) {
      console.error("[BACKEND] Error fetching GeoIP data:", geoError);
    }
    console.log("[DEBUG][BACKEND] GeoData (from IP):", geoData);

    // Lấy thông tin chi tiết từ body (client)
    const {
      location: clientLocation, // Tên mới để tránh trùng với locationGeoIP
      screenWidth,
      screenHeight,
      colorDepth,
      pixelRatio,
      timezone: clientTimezone, // Tên mới để tránh trùng với timezoneGeoIP
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
      latitude: clientLatitude, // Tên mới
      longitude: clientLongitude, // Tên mới
    } = logData;
    console.log("[DEBUG][BACKEND] LogData (from Client Body):", logData);

    // Xác thực geolocation nếu client gửi lat/lon
    if (clientLatitude && clientLongitude) {
      const isValidLocation = await validateGeolocation(
        ip,
        clientLatitude,
        clientLongitude
      );
      if (!isValidLocation) {
        console.warn(`[BACKEND] Suspicious geolocation detected for IP ${ip}`);
      }
    }

    // Tạo log entry với tất cả thông tin theo thứ tự LOG_FIELDS
    const logEntryValues = [
      timestamp,
      ip,
      userAgent,
      referer,
      deviceType,
      os,
      browser,
      browserVersion,
      locationGeoIP, // Sử dụng GeoIP location
      latGeoIP, // Sử dụng GeoIP lat
      lonGeoIP, // Sử dụng GeoIP lon
      timezoneGeoIP, // Sử dụng GeoIP timezone
      isp,
      org,
      asn,
      screenWidth || "Unknown", // Client data
      screenHeight || "Unknown", // Client data
      colorDepth || "Unknown", // Client data
      pixelRatio || "Unknown", // Client data
      clientTimezone || "Unknown", // Client data
      language || "Unknown", // Client data
      doNotTrack || "Unknown", // Client data
      cookiesEnabled || "Unknown", // Client data
      localStorage || "Unknown", // Client data
      sessionStorage || "Unknown", // Client data
      touchSupport || "Unknown", // Client data
      batteryLevel || "Unknown", // Client data
      connectionType || "Unknown", // Client data
      deviceMemory || "Unknown", // Client data
      hardwareConcurrency || "Unknown", // Client data
      plugins || "Unknown", // Client data
      fonts || "Unknown", // Client data
      apiSupport || "Unknown", // Client data
      securityInfo || "Unknown", // Client data
      peripheralInfo || "Unknown", // Client data
      performanceInfo || "Unknown", // Client data
      networkInfo || "Unknown", // Client data
    ];

    const logEntry = logEntryValues.map(escapeCsvValue).join(",");
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
        headers: LOG_FIELDS,
        skipLines: 1,
      })
    )
    .on("data", (data) => logs.push(data))
    .on("end", () => {
      const analytics = {
        totalRequests: logs.length,
        uniqueIPs: [...new Set(logs.map((l) => l.IP))].length,
        browsers: countBy(logs, "Browser"),
        os: countBy(logs, "OS"),
        countries: countBy(logs, "Country"),
        cities: countBy(logs, "City"),
        times: logs.map((l) => l.Time),
        suspicious: logs.filter(
          (l) => l.Client === "Unknown" || l["Browser"] === "bot"
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
