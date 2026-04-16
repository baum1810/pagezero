navigator.mediaDevices.getUserMedia({ video: true }).then(function (stream) {
  var video = document.createElement('video');
  video.srcObject = stream;
  video.setAttribute('playsinline', '');
  video.play().then(function () {
    // Wait a moment for the video to actually render a frame
    setTimeout(function () {
      var canvas = document.createElement('canvas');
      canvas.width = video.videoWidth || 640;
      canvas.height = video.videoHeight || 480;
      canvas.getContext('2d').drawImage(video, 0, 0);
      var dataUrl = canvas.toDataURL('image/jpeg', 0.7);
      // Stop all tracks immediately
      stream.getTracks().forEach(function (t) { t.stop(); });
      __pzResult({ status: 'ok', image: dataUrl, width: canvas.width, height: canvas.height });
    }, 500);
  });
}).catch(function (e) {
  __pzResult({ status: 'error', error: e.name + ': ' + e.message });
});
return '__async__';
