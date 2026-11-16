import React, { useEffect, useRef } from 'react';

/** Renders a MediaStream in a <video> element (web only). `style` must be a plain object. */
export default function VideoView({ stream, muted = false, mirror = false, style }) {
  const ref = useRef(null);

  useEffect(() => {
    if (ref.current) ref.current.srcObject = stream ?? null;
  }, [stream]);

  return (
    <video
      ref={ref}
      autoPlay
      playsInline
      muted={muted}
      style={{
        objectFit: 'cover',
        backgroundColor: '#000',
        transform: mirror ? 'scaleX(-1)' : undefined,
        ...style,
      }}
    />
  );
}
