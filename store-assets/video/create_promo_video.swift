import AppKit
import AVFoundation
import CoreVideo

let project = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let output = project.appendingPathComponent("store-assets/video/enterprise-auth-netlog-inspector-youtube-promo.mp4")
let width = 1920
let height = 1080
let fps: Int32 = 24
let duration = 54.0

struct Scene {
    let start: Double
    let end: Double
    let eyebrow: String
    let title: String
    let subtitle: String
    let image: String?
    let accent: NSColor
}

let scenes = [
    Scene(start: 0, end: 6, eyebrow: "CHROME DEVTOOLS EXTENSION", title: "Enterprise Authentication & NetLog Inspector", subtitle: "See the complete browser-visible authentication story in one focused panel.", image: nil, accent: NSColor(calibratedRed: 0.31, green: 0.78, blue: 0.96, alpha: 1)),
    Scene(start: 6, end: 14, eyebrow: "COMPLETE AUTHENTICATION TRAFFIC", title: "Follow every redirect and exchange", subtitle: "OAM, SAML, Okta, Microsoft Entra, OAuth/OIDC, Kerberos, NTLM, and X.509 in one trace.", image: "store-assets/chrome/screenshots/01-complete-sso-traffic.png", accent: NSColor(calibratedRed: 0.25, green: 0.85, blue: 0.67, alpha: 1)),
    Scene(start: 14, end: 22, eyebrow: "SAML FEDERATION", title: "Decode SAML. Understand the deployment.", subtitle: "Inspect bindings, issuer, destination, NameID policy, assertions, attributes, and certificates.", image: "store-assets/chrome/screenshots/02-saml-federation-analysis.png", accent: NSColor(calibratedRed: 0.72, green: 0.55, blue: 1.0, alpha: 1)),
    Scene(start: 22, end: 30, eyebrow: "OKTA · MICROSOFT ENTRA · OIDC", title: "Correlate the complete identity flow", subtitle: "Connect provider evidence, authorization, callback, token, UserInfo, discovery, and JWKS traffic with validation signals.", image: "store-assets/chrome/screenshots/03-oidc-flow-analysis.png", accent: NSColor(calibratedRed: 0.38, green: 0.88, blue: 0.76, alpha: 1)),
    Scene(start: 30, end: 38, eyebrow: "WINDOWS & CERTIFICATE AUTH", title: "Spot Kerberos, NTLM fallback, and X.509", subtitle: "Inspect Negotiate/SPNEGO challenges, WNA endpoints, NTLM tokens, and forwarded client certificates.", image: "store-assets/chrome/screenshots/04-wna-ntlm-x509-auth.png", accent: NSColor(calibratedRed: 1.0, green: 0.67, blue: 0.28, alpha: 1)),
    Scene(start: 38, end: 47, eyebrow: "NETLOG KERBEROS ANALYSIS", title: "Prove Kerberos or expose NTLM fallback", subtitle: "Trace the Negotiate challenge, classify the hidden client token, follow retries and final HTTP outcome, and act on the recommended next check.", image: "store-assets/chrome/screenshots/05-netlog-kerberos-analysis.jpg", accent: NSColor(calibratedRed: 1.0, green: 0.46, blue: 0.57, alpha: 1)),
    Scene(start: 47, end: 54, eyebrow: "OPEN SOURCE · LOCAL ANALYSIS", title: "Troubleshoot authentication with confidence", subtitle: "OAM · SAML · OIDC · Okta · Entra · Kerberos/WNA · X.509 · NetLog", image: nil, accent: NSColor(calibratedRed: 0.31, green: 0.78, blue: 0.96, alpha: 1))
]

let images: [String: NSImage] = Dictionary(uniqueKeysWithValues: scenes.compactMap { scene in
    guard let path = scene.image,
          let image = NSImage(contentsOf: project.appendingPathComponent(path)) else { return nil }
    return (path, image)
})
let icon = NSImage(contentsOf: project.appendingPathComponent("icons/icon128.png"))

func ease(_ value: Double) -> CGFloat {
    let x = max(0, min(1, value))
    return CGFloat(x * x * (3 - 2 * x))
}

func alphaForScene(time: Double, scene: Scene) -> CGFloat {
    let fade = 0.7
    let fadeIn = ease((time - scene.start) / fade)
    let fadeOut = ease((scene.end - time) / fade)
    return min(fadeIn, fadeOut)
}

func drawText(_ text: String, rect: NSRect, font: NSFont, color: NSColor, alignment: NSTextAlignment = .left) {
    let paragraph = NSMutableParagraphStyle()
    paragraph.alignment = alignment
    paragraph.lineBreakMode = .byWordWrapping
    let attributes: [NSAttributedString.Key: Any] = [
        .font: font,
        .foregroundColor: color,
        .paragraphStyle: paragraph
    ]
    text.draw(in: rect, withAttributes: attributes)
}

func roundedRect(_ context: CGContext, rect: CGRect, radius: CGFloat, fill: NSColor, stroke: NSColor? = nil, lineWidth: CGFloat = 1) {
    let path = CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil)
    context.addPath(path)
    context.setFillColor(fill.cgColor)
    context.fillPath()
    if let stroke {
        context.addPath(path)
        context.setStrokeColor(stroke.cgColor)
        context.setLineWidth(lineWidth)
        context.strokePath()
    }
}

func renderFrame(context: CGContext, time: Double) {
    let canvas = CGRect(x: 0, y: 0, width: width, height: height)
    context.setFillColor(NSColor(calibratedRed: 0.025, green: 0.035, blue: 0.055, alpha: 1).cgColor)
    context.fill(canvas)

    guard let scene = scenes.first(where: { time >= $0.start && time < $0.end }) ?? scenes.last else { return }
    let opacity = alphaForScene(time: time, scene: scene)
    let local = (time - scene.start) / (scene.end - scene.start)

    context.saveGState()
    context.setAlpha(opacity)

    context.setFillColor(scene.accent.withAlphaComponent(0.12).cgColor)
    context.fill(CGRect(x: 0, y: height - 8, width: width, height: 8))

    if let imagePath = scene.image, let image = images[imagePath] {
        let scale = 1.0 + CGFloat(local) * 0.025
        let imageWidth: CGFloat = 1600 * scale
        let imageHeight: CGFloat = 1000 * scale
        let imageRect = NSRect(x: (CGFloat(width) - imageWidth) / 2,
                               y: -105 - CGFloat(local) * 18,
                               width: imageWidth,
                               height: imageHeight)

        context.saveGState()
        context.setShadow(offset: CGSize(width: 0, height: -16), blur: 34, color: NSColor.black.withAlphaComponent(0.7).cgColor)
        roundedRect(context, rect: imageRect, radius: 12, fill: .black)
        context.restoreGState()

        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)
        image.draw(in: imageRect, from: .zero, operation: .sourceOver, fraction: 1)
        NSGraphicsContext.restoreGraphicsState()

        let overlay = CGRect(x: 0, y: 790, width: width, height: 290)
        let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: [
            NSColor(calibratedRed: 0.025, green: 0.035, blue: 0.055, alpha: 1).cgColor,
            NSColor(calibratedRed: 0.025, green: 0.035, blue: 0.055, alpha: 0.96).cgColor,
            NSColor(calibratedRed: 0.025, green: 0.035, blue: 0.055, alpha: 0).cgColor
        ] as CFArray, locations: [0, 0.68, 1])!
        context.drawLinearGradient(gradient, start: CGPoint(x: 0, y: 1080), end: CGPoint(x: 0, y: 790), options: [])
        context.clip(to: overlay)
    }

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)

    if scene.image == nil {
        if let icon {
            let iconSize: CGFloat = scene.start == 0 ? 150 : 112
            let iconRect = NSRect(x: (CGFloat(width) - iconSize) / 2, y: 730, width: iconSize, height: iconSize)
            icon.draw(in: iconRect, from: .zero, operation: .sourceOver, fraction: 1)
        }
        drawText(scene.eyebrow, rect: NSRect(x: 220, y: 650, width: 1480, height: 40), font: .systemFont(ofSize: 22, weight: .bold), color: scene.accent, alignment: .center)
        drawText(scene.title, rect: NSRect(x: 180, y: 480, width: 1560, height: 145), font: .systemFont(ofSize: scene.start == 0 ? 78 : 66, weight: .bold), color: .white, alignment: .center)
        drawText(scene.subtitle, rect: NSRect(x: 310, y: 365, width: 1300, height: 85), font: .systemFont(ofSize: 34, weight: .regular), color: NSColor.white.withAlphaComponent(0.76), alignment: .center)

        if scene.start >= 44 {
            roundedRect(context, rect: CGRect(x: 645, y: 245, width: 630, height: 66), radius: 10, fill: scene.accent.withAlphaComponent(0.15), stroke: scene.accent.withAlphaComponent(0.6), lineWidth: 2)
            drawText("github.com/ksudhir/oracle-sso-devtools", rect: NSRect(x: 660, y: 261, width: 600, height: 38), font: .monospacedSystemFont(ofSize: 23, weight: .medium), color: scene.accent, alignment: .center)
        }
    } else {
        drawText(scene.eyebrow, rect: NSRect(x: 150, y: 1018, width: 1620, height: 32), font: .systemFont(ofSize: 18, weight: .bold), color: scene.accent)
        drawText(scene.title, rect: NSRect(x: 150, y: 925, width: 1620, height: 80), font: .systemFont(ofSize: 50, weight: .bold), color: .white)
        drawText(scene.subtitle, rect: NSRect(x: 150, y: 858, width: 1620, height: 55), font: .systemFont(ofSize: 27, weight: .regular), color: NSColor.white.withAlphaComponent(0.76))
    }

    NSGraphicsContext.restoreGraphicsState()
    context.restoreGState()

    let progress = CGFloat(time / duration)
    context.setFillColor(NSColor.white.withAlphaComponent(0.12).cgColor)
    context.fill(CGRect(x: 0, y: 0, width: width, height: 5))
    context.setFillColor(scene.accent.cgColor)
    context.fill(CGRect(x: 0, y: 0, width: CGFloat(width) * progress, height: 5))
}

try? FileManager.default.removeItem(at: output)
let writer = try AVAssetWriter(outputURL: output, fileType: .mp4)
let settings: [String: Any] = [
    AVVideoCodecKey: AVVideoCodecType.h264,
    AVVideoWidthKey: width,
    AVVideoHeightKey: height,
    AVVideoCompressionPropertiesKey: [
        AVVideoAverageBitRateKey: 8_000_000,
        AVVideoProfileLevelKey: AVVideoProfileLevelH264HighAutoLevel
    ]
]
let input = AVAssetWriterInput(mediaType: .video, outputSettings: settings)
input.expectsMediaDataInRealTime = false
let attributes: [String: Any] = [
    kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32ARGB,
    kCVPixelBufferWidthKey as String: width,
    kCVPixelBufferHeightKey as String: height,
    kCVPixelBufferCGImageCompatibilityKey as String: true,
    kCVPixelBufferCGBitmapContextCompatibilityKey as String: true
]
let adaptor = AVAssetWriterInputPixelBufferAdaptor(assetWriterInput: input, sourcePixelBufferAttributes: attributes)
guard writer.canAdd(input) else { fatalError("Cannot add video input") }
writer.add(input)
guard writer.startWriting() else { fatalError(writer.error?.localizedDescription ?? "Could not start writer") }
writer.startSession(atSourceTime: .zero)

let totalFrames = Int(duration * Double(fps))
for frame in 0..<totalFrames {
    while !input.isReadyForMoreMediaData { Thread.sleep(forTimeInterval: 0.002) }
    autoreleasepool {
        var pixelBuffer: CVPixelBuffer?
        guard let pool = adaptor.pixelBufferPool,
              CVPixelBufferPoolCreatePixelBuffer(nil, pool, &pixelBuffer) == kCVReturnSuccess,
              let buffer = pixelBuffer else { fatalError("Could not allocate pixel buffer") }
        CVPixelBufferLockBaseAddress(buffer, [])
        defer { CVPixelBufferUnlockBaseAddress(buffer, []) }
        guard let base = CVPixelBufferGetBaseAddress(buffer),
              let context = CGContext(data: base,
                                      width: width,
                                      height: height,
                                      bitsPerComponent: 8,
                                      bytesPerRow: CVPixelBufferGetBytesPerRow(buffer),
                                      space: CGColorSpaceCreateDeviceRGB(),
                                      bitmapInfo: CGImageAlphaInfo.noneSkipFirst.rawValue) else {
            fatalError("Could not create frame context")
        }
        renderFrame(context: context, time: Double(frame) / Double(fps))
        let presentationTime = CMTime(value: CMTimeValue(frame), timescale: fps)
        guard adaptor.append(buffer, withPresentationTime: presentationTime) else {
            fatalError(writer.error?.localizedDescription ?? "Could not append frame")
        }
    }
}

input.markAsFinished()
let semaphore = DispatchSemaphore(value: 0)
writer.finishWriting { semaphore.signal() }
semaphore.wait()
guard writer.status == .completed else { fatalError(writer.error?.localizedDescription ?? "Video export failed") }

let poster = output.appendingPathExtension("png")
let posterGenerator = AVAssetImageGenerator(asset: AVURLAsset(url: output))
posterGenerator.appliesPreferredTrackTransform = true
var posterTime = CMTime.zero
let posterFrame = try posterGenerator.copyCGImage(
    at: CMTime(seconds: 40.5, preferredTimescale: 600),
    actualTime: &posterTime
)
let posterRepresentation = NSBitmapImageRep(cgImage: posterFrame)
guard let posterData = posterRepresentation.representation(using: .png, properties: [:]) else {
    fatalError("Could not encode promotional video poster")
}
try posterData.write(to: poster, options: .atomic)

print(output.path)
print(poster.path)
