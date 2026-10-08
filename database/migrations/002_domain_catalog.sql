CREATE TABLE IF NOT EXISTS domain_catalog (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT,
  status TEXT NOT NULL DEFAULT 'UNKNOWN', source_evidence_id INTEGER REFERENCES evidence(id)
);
INSERT OR IGNORE INTO domain_catalog(name,description,status) VALUES
 ('camera_core','Camera lifecycle, model and core services','INFERRED'),
 ('still_capture','Still image capture pipeline','UNKNOWN'),
 ('video_recording','Video recording pipeline','UNKNOWN'),
 ('sensor_isp','Sensor and ISP interfaces','UNKNOWN'),
 ('exposure','Exposure, ISO, shutter and aperture','UNKNOWN'),
 ('autofocus','Autofocus and manual focus','UNKNOWN'),
 ('lens','Lens communication','INFERRED'),
 ('image_processing','Image processing','UNKNOWN'),
 ('media','Media filesystem and storage','INFERRED'),
 ('display_ui','Display, UI and graphics','INFERRED'),
 ('input','Buttons and input events','INFERRED'),
 ('power','Power and battery','INFERRED'),
 ('wifi_usb','Wi-Fi, USB and networking','INFERRED'),
 ('settings_persistence','Settings, backup and persistence','INFERRED');
