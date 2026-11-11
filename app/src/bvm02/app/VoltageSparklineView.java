package bvm02.app;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.DashPathEffect;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.view.View;

import java.util.Locale;

/**
 * Lightweight, allocation-free onDraw live voltage chart tailored for Gen5W API 19.
 * Maintains a rolling in-RAM circular buffer of recent centivolt samples.
 */
public class VoltageSparklineView extends View {

    private static final int MAX_POINTS = 600; // 15 minutes @ 1.5s interval

    private final int[] samplesCentivolts = new int[MAX_POINTS];
    private int head = 0;
    private int count = 0;
    private boolean is24V = false;

    private final Paint bgPaint = new Paint();
    private final Paint gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint refPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint labelPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint emptyPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint linePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint fillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint dotPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private final Path tracePath = new Path();
    private final Path fillPath = new Path();
    private int cachedHeight = -1;

    public VoltageSparklineView(Context context) {
        super(context);
        init();
    }

    public VoltageSparklineView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public VoltageSparklineView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        float density = getResources().getDisplayMetrics().density;

        bgPaint.setStyle(Paint.Style.FILL);
        bgPaint.setColor(0xFF11141A);

        gridPaint.setStyle(Paint.Style.STROKE);
        gridPaint.setStrokeWidth(1.0f * density);
        gridPaint.setColor(0xFF232834);

        refPaint.setStyle(Paint.Style.STROKE);
        refPaint.setStrokeWidth(1.2f * density);
        refPaint.setColor(0x6638BDF8);
        refPaint.setPathEffect(new DashPathEffect(new float[]{6f * density, 5f * density}, 0f));

        labelPaint.setColor(0xFF8B95A8);
        labelPaint.setTextSize(11.5f * density);

        emptyPaint.setColor(0xFF6E7787);
        emptyPaint.setTextSize(15.0f * density);
        emptyPaint.setTextAlign(Paint.Align.CENTER);

        linePaint.setStyle(Paint.Style.STROKE);
        linePaint.setStrokeWidth(2.6f * density);
        linePaint.setStrokeJoin(Paint.Join.ROUND);
        linePaint.setStrokeCap(Paint.Cap.ROUND);
        linePaint.setColor(0xFF00A2FF);

        fillPaint.setStyle(Paint.Style.FILL);

        dotPaint.setStyle(Paint.Style.FILL);
        dotPaint.setColor(0xFF2ECC71);
    }

    public void addSample(int centivolts, boolean mode24V) {
        this.is24V = mode24V;
        int writeIdx = (head + count) % MAX_POINTS;
        if (count < MAX_POINTS) {
            samplesCentivolts[writeIdx] = centivolts;
            count++;
        } else {
            samplesCentivolts[head] = centivolts;
            head = (head + 1) % MAX_POINTS;
        }
        invalidate();
    }

    public void setSystem24V(boolean mode24V) {
        if (this.is24V != mode24V) {
            this.is24V = mode24V;
            invalidate();
        }
    }

    public void clearSamples() {
        head = 0;
        count = 0;
        invalidate();
    }

    public int getSampleCount() {
        return count;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int w = getWidth();
        int h = getHeight();
        if (w <= 0 || h <= 0) return;

        canvas.drawRect(0, 0, w, h, bgPaint);

        float density = getResources().getDisplayMetrics().density;
        float padLeft = 54f * density;
        float padRight = 16f * density;
        float padTop = 14f * density;
        float padBottom = 22f * density;

        float plotW = w - padLeft - padRight;
        float plotH = h - padTop - padBottom;
        if (plotW <= 10f || plotH <= 10f) return;

        if (h != cachedHeight) {
            cachedHeight = h;
            fillPaint.setShader(new LinearGradient(
                    0f, padTop, 0f, padTop + plotH,
                    0x550091FF, 0x050091FF, Shader.TileMode.CLAMP));
        }

        // Determine Y-axis bounds in centivolts (default 10.5V..15.0V for 12V, 21.0V..30.0V for 24V)
        int scale = is24V ? 2 : 1;
        int minCv = 1050 * scale;
        int maxCv = 1500 * scale;

        for (int i = 0; i < count; i++) {
            int cv = samplesCentivolts[(head + i) % MAX_POINTS];
            if (cv - 30 < minCv) minCv = ((cv - 30) / 50) * 50;
            if (cv + 30 > maxCv) maxCv = (((cv + 30) + 49) / 50) * 50;
        }
        if (maxCv <= minCv) maxCv = minCv + 100;

        // Horizontal grid lines (4 intervals)
        int steps = 4;
        for (int s = 0; s <= steps; s++) {
            float frac = (float) s / (float) steps;
            float y = padTop + plotH * (1.0f - frac);
            canvas.drawLine(padLeft, y, padLeft + plotW, y, gridPaint);

            int gridCv = minCv + Math.round(frac * (maxCv - minCv));
            String lbl = String.format(Locale.US, "%.1fV", gridCv / 100.0f);
            canvas.drawText(lbl, 8f * density, y + 4f * density, labelPaint);
        }

        // Nominal full resting reference line (12.60V or 25.20V)
        int nominalCv = 1260 * scale;
        if (nominalCv > minCv && nominalCv < maxCv) {
            float nomFrac = (float) (nominalCv - minCv) / (float) (maxCv - minCv);
            float nomY = padTop + plotH * (1.0f - nomFrac);
            canvas.drawLine(padLeft, nomY, padLeft + plotW, nomY, refPaint);
        }

        if (count == 0) {
            canvas.drawText(
                    "Connect to a BVM02 sensor to stream live battery voltage",
                    padLeft + plotW * 0.5f,
                    padTop + plotH * 0.52f,
                    emptyPaint
            );
            return;
        }

        tracePath.reset();
        fillPath.reset();

        float denomX = (count > 1) ? (float) (count - 1) : 1.0f;
        float lastX = padLeft;
        float lastY = padTop + plotH * 0.5f;

        for (int i = 0; i < count; i++) {
            int cv = samplesCentivolts[(head + i) % MAX_POINTS];
            float x = (count == 1) ? (padLeft + plotW * 0.5f) : (padLeft + (i / denomX) * plotW);
            float yFrac = (float) (cv - minCv) / (float) (maxCv - minCv);
            yFrac = Math.max(0.0f, Math.min(1.0f, yFrac));
            float y = padTop + plotH * (1.0f - yFrac);

            if (i == 0) {
                tracePath.moveTo(x, y);
                fillPath.moveTo(x, padTop + plotH);
                fillPath.lineTo(x, y);
            } else {
                tracePath.lineTo(x, y);
                fillPath.lineTo(x, y);
            }
            lastX = x;
            lastY = y;
        }

        if (count > 1) {
            fillPath.lineTo(lastX, padTop + plotH);
            fillPath.close();
            canvas.drawPath(fillPath, fillPaint);
            canvas.drawPath(tracePath, linePaint);
        }

        // Highlight latest reading dot
        canvas.drawCircle(lastX, lastY, 4.5f * density, dotPaint);
    }
}
