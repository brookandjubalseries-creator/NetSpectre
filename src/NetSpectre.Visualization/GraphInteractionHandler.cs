using NetSpectre.Core.Models;

namespace NetSpectre.Visualization;

public sealed class GraphInteractionHandler
{
    private readonly ForceDirectedLayout _layout;
    private readonly SkiaGraphRenderer _renderer;
    private NetworkNode? _draggedNode;
    private float _lastMouseX;
    private float _lastMouseY;
    private bool _isPanning;

    public GraphInteractionHandler(ForceDirectedLayout layout, SkiaGraphRenderer renderer)
    {
        _layout = layout;
        _renderer = renderer;
    }

    public void OnMouseDown(float screenX, float screenY, int canvasWidth, int canvasHeight, bool rightButton = false)
    {
        var (worldX, worldY) = ScreenToWorld(screenX, screenY, canvasWidth, canvasHeight);
        _lastMouseX = screenX;
        _lastMouseY = screenY;

        if (rightButton)
        {
            _isPanning = true;
            return;
        }

        _draggedNode = _layout.GetNodeAt(worldX, worldY);
        if (_draggedNode != null)
            _draggedNode.IsPinned = true;
    }

    public void OnMouseMove(float screenX, float screenY, int canvasWidth, int canvasHeight)
    {
        if (_isPanning)
        {
            _renderer.OffsetX += screenX - _lastMouseX;
            _renderer.OffsetY += screenY - _lastMouseY;
            _lastMouseX = screenX;
            _lastMouseY = screenY;
            return;
        }

        if (_draggedNode != null)
        {
            var (worldX, worldY) = ScreenToWorld(screenX, screenY, canvasWidth, canvasHeight);
            _draggedNode.X = worldX;
            _draggedNode.Y = worldY;
            _draggedNode.VelocityX = 0;
            _draggedNode.VelocityY = 0;
        }
    }

    public void OnMouseUp()
    {
        if (_draggedNode != null)
        {
            _draggedNode.IsPinned = false;
            _draggedNode = null;
        }
        _isPanning = false;
    }

    public void OnScroll(float delta)
    {
        var factor = delta > 0 ? 1.1f : 0.9f;
        _renderer.Zoom = Math.Clamp(_renderer.Zoom * factor, 0.1f, 5f);
    }

    private (float X, float Y) ScreenToWorld(float screenX, float screenY, int canvasWidth, int canvasHeight)
    {
        var worldX = (screenX - canvasWidth / 2f - _renderer.OffsetX) / _renderer.Zoom;
        var worldY = (screenY - canvasHeight / 2f - _renderer.OffsetY) / _renderer.Zoom;
        return (worldX, worldY);
    }
}
