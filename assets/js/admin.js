jQuery(document).ready(function ($) {
    function escapeHtml(str) {
        return $('<div>').text(str).html();
    }

    // --- Manual Scan ---
    $('#sp-start-scan').on('click', function () {
        var type = $('#sp-scan-type').val();
        var $progress = $('#sp-progress-area');
        var $bar = $('#sp-bar');
        var $status = $('#sp-status-text');
        var $results = $('#sp-results-area');

        $progress.show();
        $results.html('');
        $bar.css('width', '10%');
        $status.text('Scanning files...');

        $.ajax({
            url: mspData.ajaxUrl,
            type: 'POST',
            data: {
                action: 'my_security_pro_scan',
                scan_type: type,
                nonce: mspData.scanNonce
            },
            dataType: 'json',
            success: function (response) {
                $bar.css('width', '100%');
                $status.text('Scan complete!');

                var html = '<h3>Scan Results (' + escapeHtml(response.scan_type.toUpperCase()) + ')</h3>';

                if (response.results.length === 0) {
                    html += '<div class="sp-card"><p class="sp-status-ok">✅ No issues found!</p></div>';
                } else {
                    html += '<table class="sp-table"><thead><tr><th>Level</th><th>Detail</th></tr></thead><tbody>';
                    response.results.forEach(function (item) {
                        var badgeClass = 'sp-badge sp-badge-' + item.level.toLowerCase();
                        html += '<tr><td><span class="' + badgeClass + '">' + escapeHtml(item.level) + '</span></td><td>' + escapeHtml(item.msg) + '</td></tr>';
                    });
                    html += '</tbody></table>';
                }
                $results.html(html);
            },
            error: function () {
                $status.text('Connection error.');
            }
        });
    });

    // --- Dashboard: automatic header fix ---
    $('#sp-fix-headers-btn').on('click', function () {
        var $btn = $(this);
        var $result = $('#sp-fix-headers-result');
        $btn.prop('disabled', true).text('Applying...');

        $.post(mspData.ajaxUrl, {
            action: 'my_security_pro_fix_headers',
            nonce: mspData.fixHeadersNonce
        }, function (response) {
            var cls = response.success ? 'sp-status-ok' : 'sp-status-critical';
            $result.html('<div class="sp-card"><p class="' + cls + '">' + escapeHtml(response.message) + '</p></div>');
            $btn.prop('disabled', false).text('🔧 Auto-Fix Headers');
            setTimeout(function () { location.reload(); }, 2000);
        }).fail(function () {
            $result.html('<div class="sp-card"><p class="sp-status-critical">Connection error.</p></div>');
            $btn.prop('disabled', false).text('🔧 Auto-Fix Headers');
        });
    });
});
