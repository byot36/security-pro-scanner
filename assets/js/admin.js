jQuery(document).ready(function ($) {
    function escapeHtml(str) {
        return $('<div>').text(str).html();
    }

    // --- Manual Scan ---
    $('#msp-start-scan').on('click', function () {
        var type = $('#msp-scan-type').val();
        var $progress = $('#msp-progress-area');
        var $bar = $('#msp-bar');
        var $status = $('#msp-status-text');
        var $results = $('#msp-results-area');

        $progress.show();
        $results.html('');
        $bar.css('width', '10%');
        $status.text(mspData.strings.scanning);

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
                $status.text(mspData.strings.scanComplete);

                var html = '<h3>Scan Results (' + escapeHtml(response.scan_type.toUpperCase()) + ')</h3>';

                if (response.results.length === 0) {
                    html += '<div class="msp-card"><p class="msp-status-ok">✅ ' + escapeHtml(mspData.strings.noIssuesFound) + '</p></div>';
                } else {
                    html += '<table class="msp-table"><thead><tr><th>' + escapeHtml(mspData.strings.levelColumn) + '</th><th>' + escapeHtml(mspData.strings.detailColumn) + '</th></tr></thead><tbody>';
                    response.results.forEach(function (item) {
                        var badgeClass = 'msp-badge msp-badge-' + item.level.toLowerCase();
                        html += '<tr><td><span class="' + badgeClass + '">' + escapeHtml(item.level) + '</span></td><td>' + escapeHtml(item.msg) + '</td></tr>';
                    });
                    html += '</tbody></table>';
                }
                $results.html(html);
            },
            error: function () {
                $status.text(mspData.strings.connectionError);
            }
        });
    });

    // --- Dashboard: automatic header fix ---
    $('#msp-fix-headers-btn').on('click', function () {
        var $btn = $(this);
        var $result = $('#msp-fix-headers-result');
        $btn.prop('disabled', true).text(mspData.strings.applying);

        $.post(mspData.ajaxUrl, {
            action: 'my_security_pro_fix_headers',
            nonce: mspData.fixHeadersNonce
        }, function (response) {
            var cls = response.success ? 'msp-status-ok' : 'msp-status-critical';
            $result.html('<div class="msp-card"><p class="' + cls + '">' + escapeHtml(response.message) + '</p></div>');
            $btn.prop('disabled', false).text('🔧 ' + mspData.strings.autoFixHeaders);
            setTimeout(function () { location.reload(); }, 2000);
        }).fail(function () {
            $result.html('<div class="msp-card"><p class="msp-status-critical">' + escapeHtml(mspData.strings.connectionError) + '</p></div>');
            $btn.prop('disabled', false).text('🔧 ' + mspData.strings.autoFixHeaders);
        });
    });
});
